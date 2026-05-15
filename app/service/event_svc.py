import asyncio
import json
import websockets

from datetime import datetime, timezone

from app.service.interfaces.i_event_svc import EventServiceInterface
from app.utility.base_service import BaseService


class _InProcessSocket:
    """Lightweight stand-in for a websocket connection, used to deliver an
    event payload directly to an in-process subscriber. The previous design
    opened a fresh localhost websocket connection on every fire_event call;
    under load that buried the asyncio loop in handshakes and surfaced as
    504 Gateway Timeouts on otherwise-unrelated HTTP requests.
    """

    def __init__(self, payload):
        self._payload = payload
        self._consumed = False

    async def recv(self):
        if self._consumed:
            # Mimic a normal close once the single payload has been delivered.
            raise websockets.exceptions.ConnectionClosedOK(None, None)
        self._consumed = True
        return self._payload

    async def send(self, _message):
        pass

    async def close(self):
        pass

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._consumed:
            raise StopAsyncIteration
        self._consumed = True
        return self._payload


class EventService(EventServiceInterface, BaseService):

    HANDLER_TIMEOUT_S = 30

    def __init__(self):
        self.log = self.add_service('event_svc', self)
        self.contact_svc = self.get_service('contact_svc')
        self.ws_uri = 'ws://{}'.format(self.get_config('app.contact.websocket'))
        self.global_listeners = []
        self.default_exchange = 'caldera'
        self.default_queue = 'general'
        self._cached_ws_handler = None

    async def observe_event(self, callback, exchange=None, queue=None):
        """
        Register a callback for a certain event. Callback is fired when
        an event of that type is observed.

        :param callback: Callback function
        :type callback: function
        :param exchange: event exchange
        :type exchange: str
        :param queue: event queue
        :type queue: str
        """
        exchange = exchange or self.default_exchange
        queue = queue or self.default_queue
        path = '/'.join([exchange, queue])
        handle = _Handle(path, callback)
        ws_contact = await self.contact_svc.get_contact('websocket')
        ws_contact.handler.handles.append(handle)

    async def register_global_event_listener(self, callback):
        """
        Register a global event listener that is fired when any event
        is fired.

        :param callback: Callback function
        :type callback: function
        """
        self.global_listeners.append(callback)

    async def notify_global_event_listeners(self, event, **callback_kwargs):
        """
        Notify all registered global event listeners when an event is fired.

        :param event: Event string (i.e. '<exchange>/<queue>')
        :type event: str
        """
        # Snapshot listeners — a callback may register/unregister during dispatch.
        for c in list(self.global_listeners):
            try:
                c(event, **callback_kwargs)
            except Exception as e:
                self.log.error("Global callback error: %s", e, exc_info=True)

    async def handle_exceptions(self, awaitable):
        try:
            return await awaitable
        except websockets.exceptions.ConnectionClosedOK:
            pass
        except Exception as e:
            self.log.error("WebSocket error: %s", e, exc_info=True)

    async def fire_event(self, exchange=None, queue=None, timestamp=True, **callback_kwargs):
        exchange = exchange or self.default_exchange
        queue = queue or self.default_queue
        metadata = {}
        if timestamp:
            metadata.update(dict(timestamp=datetime.now(timezone.utc).timestamp()))
        callback_kwargs.update(dict(metadata=metadata))
        event = '/'.join([exchange, queue])
        if self.global_listeners:
            asyncio.get_event_loop().create_task(
                self.notify_global_event_listeners(event, **callback_kwargs))
        # In-process dispatch — bypasses the localhost TCP loopback the bus
        # originally relied on. The old path opened a brand-new websocket
        # connection per event and awaited the handshake inline, which under
        # any concurrent load (multiple agents, parallel logins, an active
        # operation) starved the asyncio loop and turned every unrelated HTTP
        # request into a 504.
        await self._dispatch_in_process(event, json.dumps(callback_kwargs))

    async def _dispatch_in_process(self, event, payload):
        handler = await self._get_ws_handler()
        if handler is None:
            return
        # Snapshot in case observe_event mutates handles during iteration.
        matched = [h for h in list(handler.handles) if event.startswith(h.tag)]
        for handle in matched:
            asyncio.get_event_loop().create_task(
                self._safe_dispatch(handler, handle, event, payload))

    async def _safe_dispatch(self, handler, handle, event, payload):
        socket = _InProcessSocket(payload)
        try:
            await asyncio.wait_for(
                handle.run(socket, '/' + event, handler.services),
                timeout=self.HANDLER_TIMEOUT_S)
        except asyncio.TimeoutError:
            self.log.warning("Event handler '%s' timed out on %s", handle.tag, event)
        except websockets.exceptions.ConnectionClosedOK:
            pass
        except Exception as e:
            # One bad subscriber must not break delivery to the others or
            # back-propagate into the publisher (e.g. Operation.run).
            self.log.error("Event handler '%s' failed on %s: %s",
                           handle.tag, event, e, exc_info=True)

    async def _get_ws_handler(self):
        if self._cached_ws_handler is not None:
            return self._cached_ws_handler
        try:
            ws_contact = await self.contact_svc.get_contact('websocket')
        except Exception as e:
            self.log.debug("Could not fetch websocket contact: %s", e)
            return None
        self._cached_ws_handler = getattr(ws_contact, 'handler', None) if ws_contact else None
        return self._cached_ws_handler


class _Handle:

    def __init__(self, tag, callback):
        self.tag = tag
        self.callback = callback

    async def run(self, socket, path, services):
        return await self.callback(socket, path, services)
