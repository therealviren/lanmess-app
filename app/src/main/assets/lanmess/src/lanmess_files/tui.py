import asyncio
import base64
import socket
import time

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import (
    Container,
    Horizontal,
    Vertical,
)
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    RichLog,
    Static,
)

from .config import (
    ADD_RATE_LIMIT_SECONDS,
    APP_NAME,
    APP_VERSION,
    CONTROL_REPLAY_WINDOW,
    DB_PATH,
    MAX_GROUP_CODE_LEN,
    MAX_MESSAGE_LEN,
    MIN_GROUP_CODE_LEN,
    MSG_RATE_LIMIT_SECONDS,
    TCP_PORT_RANGE,
    ensure_dirs,
)
from .crypto import (
    compute_secure_code_tag,
    compute_totp,
    derive_group_key,
    derive_lookup_key,
    ed_private_from_bytes,
    ed_private_to_bytes,
    ed_public_from_bytes,
    ed_public_to_bytes,
    generate_ed25519_private,
    generate_totp_secret,
    pairwise_decrypt,
    pairwise_encrypt,
    sign_bytes,
    totp_remaining,
    verify_bytes,
    verify_totp,
    x25519_generate,
    x25519_private_from_bytes,
    x25519_private_to_bytes,
    x25519_public_from_bytes,
    x25519_public_to_bytes,
)
from .database import Database
from .discovery import Discovery
from .network import Server, send_request


def _now_ms():
    return int(time.time() * 1000)


class ConfirmScreen(ModalScreen):
    CSS = """
    ConfirmScreen {
        align: center middle;
    }
    #confirm-box {
        width: 70;
        height: auto;
        border: thick $warning;
        padding: 2 3;
        background: $surface;
    }
    #confirm-message {
        padding: 0 0 1 0;
        text-align: center;
    }
    #confirm-buttons {
        height: auto;
    }
    #confirm-buttons Button {
        width: 100%;
        margin: 0 0 1 0;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    def __init__(self, message):
        super().__init__()
        self.message = message

    def compose(self) -> ComposeResult:
        with Container(id="confirm-box"):
            yield Static(
                self.message, id="confirm-message"
            )
            with Vertical(id="confirm-buttons"):
                yield Button(
                    "Confirm", id="confirm", variant="error"
                )
                yield Button(
                    "Cancel", id="cancel", variant="primary"
                )

    def on_button_pressed(self, event):
        if event.button.id == "confirm":
            self.dismiss(True)
        else:
            self.dismiss(False)

    def action_cancel(self):
        self.dismiss(False)


class HelpScreen(ModalScreen):
    CSS = """
    HelpScreen {
        align: center middle;
    }
    #help-box {
        width: 78;
        height: auto;
        border: thick $accent;
        padding: 2 3;
        background: $surface;
    }
    #help-title {
        text-align: center;
        text-style: bold;
        color: $accent;
        padding: 0 0 1 0;
    }
    #help-content {
        height: auto;
    }
    #help-close {
        width: 100%;
        margin: 1 0 0 0;
    }
    """

    BINDINGS = [
        Binding("escape", "close", "Close", show=False),
        Binding("q", "close", "Close", show=False),
    ]

    def compose(self) -> ComposeResult:
        with Container(id="help-box"):
            yield Static(
                "Commands & Keys", id="help-title"
            )
            yield Static(
                "Commands:\n"
                "  /help      Show this help\n"
                "  /clear     Clear local history\n"
                "  /clearall  Ask contact to clear both sides\n"
                "  /stop      Stop the chat\n"
                "  /del <id>  Delete message #id\n"
                "  /del       Delete most recent message\n"
                "\n"
                "Keys:\n"
                "  A          Add by 8-digit code\n"
                "  S          Start chat\n"
                "  Y          Accept pending\n"
                "  X          Reject pending\n"
                "  C          Clear local chat\n"
                "  D          Delete contact\n"
                "  T          Stop chat\n"
                "  Ctrl+R     Reset all data\n"
                "  F5         Refresh\n"
                "  Ctrl+Q     Quit\n"
                "\n"
                "Security:\n"
                "  Messages use per-pair X25519 ECDH\n"
                "  AES-256-GCM, HKDF-SHA256, Ed25519\n"
                "  signatures, monotonic counters.\n"
                "  Group code protects data at rest.",
                id="help-content",
            )
            yield Button(
                "Close", id="help-close", variant="primary"
            )

    def on_button_pressed(self, event):
        if event.button.id == "help-close":
            self.dismiss()

    def action_close(self):
        self.dismiss()


class StartupScreen(Screen):
    CSS = """
    StartupScreen {
        align: center middle;
    }
    #startup-box {
        width: 72;
        height: auto;
        border: thick $primary;
        padding: 2 3;
        background: $surface;
    }
    #startup-title {
        text-align: center;
        text-style: bold;
        padding: 0 0 1 0;
        color: $accent;
    }
    #startup-welcome {
        text-align: center;
        padding: 0 0 1 0;
    }
    #startup-note {
        text-align: center;
        color: $text-muted;
        padding: 0 0 1 0;
    }
    StartupScreen Input {
        margin: 0 0 1 0;
    }
    StartupScreen Button {
        width: 100%;
        margin: 0 0 1 0;
    }
    #startup-error {
        color: $error;
        height: auto;
        padding: 1 0 0 0;
        text-align: center;
    }
    """

    def __init__(self, db):
        super().__init__()
        self.db = db
        self.has_identity = db.has_identity()

    def compose(self) -> ComposeResult:
        with Container(id="startup-box"):
            yield Static(
                f"{APP_NAME} v{APP_VERSION}",
                id="startup-title",
            )
            if self.has_identity:
                yield Static(
                    "Enter your group code to unlock.",
                    id="startup-welcome",
                )
                yield Static(
                    "Data at rest is encrypted with this "
                    "code. There is no recovery.",
                    id="startup-note",
                )
                yield Input(
                    placeholder="Group code",
                    password=True,
                    id="group_code",
                )
                yield Button(
                    "Unlock", id="login", variant="primary"
                )
                yield Button(
                    "Reset all data",
                    id="reset",
                    variant="error",
                )
            else:
                yield Input(
                    placeholder="Your display name",
                    id="name",
                )
                yield Input(
                    placeholder=(
                        f"Group code "
                        f"(min {MIN_GROUP_CODE_LEN} chars)"
                    ),
                    password=True,
                    id="group_code",
                )
                yield Button(
                    "Create", id="create", variant="primary"
                )
            yield Static("", id="startup-error")

    def refresh_state(self):
        new_has = self.db.has_identity()
        if new_has != self.has_identity:
            self.has_identity = new_has
            self.refresh(recompose=True)

    async def on_input_submitted(self, event):
        if event.input.id == "group_code":
            await self._submit()

    async def on_button_pressed(self, event):
        if event.button.id == "reset":
            self.app.push_screen(
                ConfirmScreen(
                    "RESET EVERYTHING?\n"
                    "This wipes your identity, contacts, "
                    "and all messages. Irreversible."
                ),
                callback=self._on_reset_confirmed,
            )
            return
        if event.button.id in ("login", "create"):
            await self._submit()

    def _on_reset_confirmed(self, confirmed):
        if confirmed:
            asyncio.create_task(self.app.perform_reset())

    async def _submit(self):
        try:
            if self.has_identity:
                code = self.query_one(
                    "#group_code", Input
                ).value
                if not code:
                    self.query_one(
                        "#startup-error", Static
                    ).update("Group code required.")
                    return
                ok = await self.app.login(code)
                if not ok:
                    self.query_one(
                        "#startup-error", Static
                    ).update("Wrong group code.")
            else:
                name = self.query_one(
                    "#name", Input
                ).value.strip()
                code = self.query_one(
                    "#group_code", Input
                ).value
                if not name or not code:
                    self.query_one(
                        "#startup-error", Static
                    ).update(
                        "Name and group code required."
                    )
                    return
                if not self.app._valid_name(name):
                    self.query_one(
                        "#startup-error", Static
                    ).update(
                        "Name must be 1-40 chars, "
                        "no control characters."
                    )
                    return
                if len(code) < MIN_GROUP_CODE_LEN:
                    self.query_one(
                        "#startup-error", Static
                    ).update(
                        f"Group code must be at least "
                        f"{MIN_GROUP_CODE_LEN} characters."
                    )
                    return
                if len(code) > MAX_GROUP_CODE_LEN:
                    self.query_one(
                        "#startup-error", Static
                    ).update(
                        f"Group code too long "
                        f"(max {MAX_GROUP_CODE_LEN})."
                    )
                    return
                await self.app.create_identity(name, code)
        except Exception as exc:
            self.query_one(
                "#startup-error", Static
            ).update(str(exc))


class ContactItem(ListItem):
    def __init__(
        self,
        name,
        chat_started,
        incoming_request,
        blocked,
        pending,
        clear_pending,
    ):
        if pending == 2:
            label = f"{name}  [accept?]"
        elif blocked:
            label = f"{name}  [BLOCKED]"
        elif clear_pending:
            label = f"{name}  [clear?]"
        elif pending == 1:
            label = f"{name}  [waiting]"
        elif incoming_request:
            label = f"{name}  [chat req]"
        elif chat_started:
            label = f"{name}  [active]"
        else:
            label = f"{name}"
        super().__init__(Label(label))
        self.contact_name = name


class MainScreen(Screen):
    CSS = """
    #main-layout {
        height: 1fr;
    }
    #sidebar {
        width: 40;
        border-right: solid $primary;
        padding: 1;
    }
    #sidebar-title {
        text-align: center;
        text-style: bold;
        padding: 0 0 1 0;
        color: $accent;
    }
    #contacts {
        height: 1fr;
    }
    #action-buttons {
        height: auto;
        margin: 1 0 0 0;
    }
    #action-buttons Button {
        width: 100%;
        margin: 0 0 1 0;
    }
    #login-code {
        text-align: center;
        padding: 1 0 0 0;
        color: $success;
    }
    #add-code {
        margin: 0;
    }
    #chat-area {
        width: 1fr;
        padding: 0 1;
    }
    #messages {
        height: 1fr;
        border: solid $primary;
        padding: 0 1;
    }
    #message-input {
        margin: 1 0;
    }
    """

    BINDINGS = [
        Binding("ctrl+q", "quit_app", "Quit", show=True),
        Binding("a", "focus_add", "Add", show=True),
        Binding("s", "start_chat", "Start", show=True),
        Binding("y", "accept", "Accept", show=True),
        Binding("x", "reject", "Reject", show=True),
        Binding("c", "clear_chat", "Clear", show=True),
        Binding("d", "delete_contact", "Delete", show=True),
        Binding("t", "stop_chat", "Stop", show=True),
        Binding("ctrl+r", "reset_all", "Reset", show=True),
        Binding("f5", "refresh", "Refresh", show=True),
    ]

    def __init__(self):
        super().__init__()
        self.current_contact = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main-layout"):
            with Vertical(id="sidebar"):
                yield Static(
                    "Contacts", id="sidebar-title"
                )
                yield ListView(id="contacts")
                with Vertical(id="action-buttons"):
                    yield Button(
                        "Start (S)",
                        id="btn-start",
                        variant="primary",
                    )
                    yield Button(
                        "Accept (Y)",
                        id="btn-accept",
                        variant="success",
                    )
                    yield Button(
                        "Stop (T)",
                        id="btn-stop",
                        variant="warning",
                    )
                yield Static("", id="login-code")
                yield Input(
                    placeholder="Add by 8-digit code...",
                    id="add-code",
                    max_length=8,
                )
            with Vertical(id="chat-area"):
                yield RichLog(
                    id="messages",
                    markup=False,
                    wrap=True,
                )
                yield Input(
                    placeholder="Message or /command "
                    "(/help for list)...",
                    id="message-input",
                )
        yield Footer()

    def on_mount(self):
        self.refresh_contacts()
        self.set_interval(1.0, self.tick)
        self.load_messages_for(None)

    def tick(self):
        try:
            code = compute_totp(self.app.totp_secret)
            remaining = totp_remaining()
            self.query_one(
                "#login-code", Static
            ).update(
                f"Login code\n[bold]{code}[/bold]\n"
                f"{remaining}s"
            )
        except Exception:
            pass

    def refresh_contacts(self):
        lv = self.query_one("#contacts", ListView)
        lv.clear()
        for c in self.app.db.get_contacts():
            lv.append(
                ContactItem(
                    c["name"],
                    c.get("chat_started", 0),
                    c.get("incoming_request", 0),
                    c.get("blocked", 0),
                    c.get("pending", 0),
                    c.get("clear_pending", 0),
                )
            )
        if self.current_contact:
            for index, item in enumerate(list(lv.children)):
                if (
                    isinstance(item, ContactItem)
                    and item.contact_name
                    == self.current_contact
                ):
                    lv.index = index
                    break

    def load_messages_for(self, contact_name):
        self.current_contact = contact_name
        log = self.query_one("#messages", RichLog)
        log.clear()
        if not contact_name:
            log.write("Select a contact on the left.")
            return
        contact = self.app.db.get_contact(contact_name)
        if contact and contact.get("blocked"):
            log.write(
                "[BLOCKED CONTACT - messages hidden]"
            )
            return
        if contact and not contact.get("x25519_public_hex"):
            log.write(
                "[This contact predates pairwise E2EE. "
                "Delete and re-add them to chat.]"
            )
            return
        for m in self.app.db.get_messages(contact_name):
            ts = time.strftime(
                "%H:%M", time.localtime(m["timestamp"])
            )
            who = (
                "You"
                if m["direction"] == "out"
                else contact_name
            )
            log.write(
                f"[#{m['id']}] [{ts}] {who}: "
                f"{m['content']}"
            )

    def on_list_view_selected(self, event):
        if isinstance(event.item, ContactItem):
            self.load_messages_for(
                event.item.contact_name
            )

    async def on_button_pressed(self, event):
        if event.button.id == "btn-start":
            await self.action_start_chat()
        elif event.button.id == "btn-accept":
            await self.action_accept()
        elif event.button.id == "btn-stop":
            self.action_stop_chat()

    async def on_input_submitted(self, event):
        if event.input.id == "add-code":
            code = event.value.strip()
            event.input.value = ""
            if len(code) != 8 or not code.isdigit():
                self.app.notify(
                    "Code must be exactly 8 digits.",
                    severity="error",
                )
                return
            await self.app.add_contact_by_code(code)
        elif event.input.id == "message-input":
            text = event.value
            if not text.strip():
                return
            event.input.value = ""
            if text.startswith("/"):
                await self.handle_command(text.strip())
                return
            if not self.current_contact:
                self.app.notify(
                    "Select a contact first.",
                    severity="error",
                )
                return
            await self.app.send_chat_message(
                self.current_contact, text
            )

    async def handle_command(self, cmd):
        parts = cmd.split(None, 1)
        name = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""
        if name == "/help":
            self.app.push_screen(HelpScreen())
            return
        if not self.current_contact:
            self.app.notify(
                "Select a contact first.", severity="error"
            )
            return
        contact = self.app.db.get_contact(
            self.current_contact
        )
        if not contact:
            return
        if name == "/clear":
            self.app.clear_chat_confirm(
                self.current_contact
            )
        elif name == "/clearall":
            self.app.clear_all_confirm(
                self.current_contact
            )
        elif name == "/stop":
            self.app.stop_chat_confirm(
                self.current_contact
            )
        elif name == "/del":
            if arg:
                try:
                    mid = int(arg)
                except ValueError:
                    self.app.notify(
                        "Usage: /del <id>",
                        severity="error",
                    )
                    return
                self.app.delete_message_confirm(mid)
            else:
                msgs = self.app.db.get_messages(
                    self.current_contact, limit=1
                )
                if not msgs:
                    self.app.notify(
                        "No messages to delete.",
                        severity="error",
                    )
                    return
                self.app.delete_message_confirm(
                    msgs[0]["id"]
                )
        else:
            self.app.notify(
                f"Unknown command: {name}. Try /help.",
                severity="error",
            )

    def action_focus_add(self):
        self.query_one("#add-code", Input).focus()

    async def action_start_chat(self):
        if not self.current_contact:
            self.app.notify(
                "Select a contact first.", severity="error"
            )
            return
        await self.app.start_chat(self.current_contact)

    async def action_accept(self):
        if not self.current_contact:
            self.app.notify(
                "Select a contact first.", severity="error"
            )
            return
        contact = self.app.db.get_contact(
            self.current_contact
        )
        if not contact:
            return
        if contact.get("pending") == 2:
            await self.app.accept_contact(
                self.current_contact
            )
        elif contact.get("clear_pending"):
            await self.app.accept_clear(
                self.current_contact
            )
        elif contact.get("incoming_request"):
            await self.app.accept_chat(
                self.current_contact
            )
        else:
            self.app.notify(
                "Nothing to accept for this contact."
            )

    async def action_reject(self):
        if not self.current_contact:
            self.app.notify(
                "Select a contact first.", severity="error"
            )
            return
        contact = self.app.db.get_contact(
            self.current_contact
        )
        if not contact:
            return
        if contact.get("pending") == 2:
            await self.app.reject_contact(
                self.current_contact
            )
        elif contact.get("clear_pending"):
            await self.app.reject_clear(
                self.current_contact
            )
        elif contact.get("incoming_request"):
            await self.app.reject_chat(
                self.current_contact
            )
        else:
            self.app.notify(
                "Nothing to reject for this contact."
            )

    def action_clear_chat(self):
        if not self.current_contact:
            self.app.notify(
                "Select a contact first.", severity="error"
            )
            return
        self.app.clear_chat_confirm(
            self.current_contact
        )

    def action_delete_contact(self):
        if not self.current_contact:
            self.app.notify(
                "Select a contact first.", severity="error"
            )
            return
        self.app.delete_contact_confirm(
            self.current_contact
        )

    def action_stop_chat(self):
        if not self.current_contact:
            self.app.notify(
                "Select a contact first.", severity="error"
            )
            return
        self.app.stop_chat_confirm(
            self.current_contact
        )

    def action_reset_all(self):
        self.app.push_screen(
            ConfirmScreen(
                "RESET EVERYTHING?\n"
                "This wipes your identity, contacts, "
                "and all messages."
            ),
            callback=self._on_reset_confirmed,
        )

    def _on_reset_confirmed(self, confirmed):
        if confirmed:
            asyncio.create_task(
                self.app.perform_reset()
            )

    def action_refresh(self):
        self.refresh_contacts()

    def action_quit_app(self):
        self.app.exit()


class LanMessApp(App):
    TITLE = f"{APP_NAME} {APP_VERSION}"
    CSS = """
    Screen {
        background: $surface;
    }
    """

    def __init__(self):
        super().__init__()
        ensure_dirs()
        self.db = Database(DB_PATH)
        self.discovery = Discovery()
        self.server = None
        self.broadcast_task = None
        self.group_key = None
        self.lookup_key = None
        self.totp_secret = None
        self.ed_private = None
        self.ed_public = None
        self.x25519_private = None
        self.x25519_public = None
        self.user_name = None
        self.tcp_port = None
        self._add_attempts = {}
        self._msg_attempts = {}

    def on_mount(self):
        self.push_screen(StartupScreen(self.db))

    def _valid_name(self, s):
        if not isinstance(s, str) or not (
            1 <= len(s) <= 40
        ):
            return False
        return not any(ord(c) < 32 for c in s)

    def _valid_hex(self, s, nbytes):
        if not isinstance(s, str) or len(s) != nbytes * 2:
            return False
        try:
            bytes.fromhex(s)
            return True
        except ValueError:
            return False

    def _valid_code(self, s):
        return (
            isinstance(s, str)
            and len(s) == 8
            and s.isdigit()
        )

    def _valid_timestamp(self, ts):
        if not isinstance(ts, int):
            return False
        now_ms = _now_ms()
        return abs(now_ms - ts) <= int(
            CONTROL_REPLAY_WINDOW * 1000
        )

    def _resolve_peer_address(self, contact):
        peer = self.discovery.find_by_name(
            contact["name"]
        )
        if peer:
            return peer["ip"], peer["tcp_port"]
        if contact.get("ip") and contact.get("port"):
            return contact["ip"], int(contact["port"])
        return None, None

    async def create_identity(self, name, group_code):
        key = derive_group_key(group_code)
        sk_ed = generate_ed25519_private()
        pk_ed = sk_ed.public_key()
        sk_x = x25519_generate()
        pk_x = sk_x.public_key()
        totp = generate_totp_secret()
        port = self._find_free_port()
        self.db.create_identity(
            name=name,
            group_key=key,
            ed_private_hex=ed_private_to_bytes(sk_ed).hex(),
            ed_public_hex=ed_public_to_bytes(pk_ed).hex(),
            totp_secret_hex=totp.hex(),
            tcp_port=port,
            x25519_private_hex=x25519_private_to_bytes(
                sk_x
            ).hex(),
            x25519_public_hex=x25519_public_to_bytes(
                pk_x
            ).hex(),
        )
        await self._start_session()

    async def login(self, group_code):
        key = derive_group_key(group_code)
        if not self.db.unlock(key):
            return False
        await self._start_session()
        return True

    def _find_free_port(self):
        for port in range(
            TCP_PORT_RANGE[0], TCP_PORT_RANGE[1]
        ):
            s = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM
            )
            try:
                s.bind(("0.0.0.0", port))
                s.close()
                return port
            except OSError:
                try:
                    s.close()
                except Exception:
                    pass
        raise RuntimeError(
            "No free TCP port available"
        )

    async def _start_session(self):
        try:
            identity = self.db.get_identity()
            if not identity:
                raise RuntimeError("No identity found")
            self.user_name = identity["name"]
            self.group_key = self.db.key
            self.lookup_key = derive_lookup_key(
                self.group_key
            )
            self.totp_secret = bytes.fromhex(
                identity["totp_secret_hex"]
            )
            self.ed_private = ed_private_from_bytes(
                bytes.fromhex(identity["ed_private_hex"])
            )
            self.ed_public = ed_public_from_bytes(
                bytes.fromhex(identity["ed_public_hex"])
            )
            self.x25519_private = x25519_private_from_bytes(
                bytes.fromhex(
                    identity["x25519_private_hex"]
                )
            )
            self.x25519_public = x25519_public_from_bytes(
                bytes.fromhex(
                    identity["x25519_public_hex"]
                )
            )
            self.tcp_port = int(identity["tcp_port"])

            self.server = Server(
                self.tcp_port, self.handle_incoming
            )
            try:
                await self.server.start()
            except OSError:
                new_port = self._find_free_port()
                self.db.update_tcp_port(new_port)
                self.tcp_port = new_port
                self.server = Server(
                    self.tcp_port, self.handle_incoming
                )
                await self.server.start()

            await self.discovery.start()
            self.broadcast_task = asyncio.create_task(
                self.discovery.broadcaster(
                    self.user_name,
                    self.tcp_port,
                    ed_public_to_bytes(
                        self.ed_public
                    ).hex(),
                    x25519_public_to_bytes(
                        self.x25519_public
                    ).hex(),
                    self._current_code_tag,
                )
            )
            self.push_screen(MainScreen())
        except Exception as exc:
            self.notify(
                f"Startup error: {exc}",
                severity="error",
            )

    def _current_code_tag(self):
        code = compute_totp(self.totp_secret)
        return compute_secure_code_tag(
            self.lookup_key, code
        )

    def _sign_control(self, fields):
        data = "|".join(
            str(fields[k]) for k in sorted(fields)
        ).encode("utf-8")
        return base64.b64encode(
            sign_bytes(self.ed_private, data)
        ).decode("ascii")

    def _verify_control(self, fields, pk, sig_b64):
        try:
            sig = base64.b64decode(sig_b64)
        except Exception:
            return False
        data = "|".join(
            str(fields[k]) for k in sorted(fields)
        ).encode("utf-8")
        return verify_bytes(pk, sig, data)

    async def add_contact_by_code(self, code):
        tag = compute_secure_code_tag(
            self.lookup_key, code
        )
        (
            found_name,
            info,
        ) = self.discovery.find_by_code_tag(
            tag, exclude_name=self.user_name
        )
        if not found_name:
            self.notify(
                "Searching for peer...", timeout=2
            )
            await asyncio.sleep(3.0)
            (
                found_name,
                info,
            ) = self.discovery.find_by_code_tag(
                tag, exclude_name=self.user_name
            )
        if not found_name:
            self.notify(
                "No peer found with that code.",
                severity="error",
            )
            return
        fields = {
            "from_name": self.user_name,
            "from_ed_pub": ed_public_to_bytes(
                self.ed_public
            ).hex(),
            "from_x25519_pub": x25519_public_to_bytes(
                self.x25519_public
            ).hex(),
            "from_port": self.tcp_port,
            "code": code,
            "timestamp": _now_ms(),
        }
        payload = {
            "type": "ADD_REQUEST",
            **fields,
            "signature": self._sign_control(fields),
        }
        resp = await send_request(
            info["ip"], info["tcp_port"], payload
        )
        if not resp:
            self.notify(
                "Add failed: unreachable.",
                severity="error",
            )
            return
        resp_type = resp.get("type")
        if resp_type == "ADD_REJECT":
            self.notify(
                f"Add failed: "
                f"{resp.get('reason', 'rejected')}",
                severity="error",
            )
            return
        if resp_type not in (
            "ADD_ACCEPT",
            "ADD_PENDING",
        ):
            self.notify(
                "Invalid peer response.",
                severity="error",
            )
            return
        to_ed = resp.get("to_ed_pub", "")
        to_x = resp.get("to_x25519_pub", "")
        if not self._valid_hex(to_ed, 32) or not (
            self._valid_hex(to_x, 32)
        ):
            self.notify(
                "Invalid peer keys.", severity="error"
            )
            return
        existing = self.db.get_contact(found_name)
        if (
            existing
            and existing["ed_public_hex"] != to_ed
        ):
            self.notify(
                f"Key mismatch for {found_name}. "
                "Refusing to overwrite.",
                severity="error",
            )
            return
        self.db.upsert_contact(
            name=found_name,
            ip=info["ip"],
            port=info["tcp_port"],
            ed_public_hex=to_ed,
            x25519_public_hex=to_x,
        )
        if resp_type == "ADD_ACCEPT":
            self.db.set_contact_state(
                found_name, pending=0
            )
            self.notify(f"Added {found_name}.")
        else:
            self.db.set_contact_state(
                found_name, pending=1
            )
            self.notify(
                f"Request sent to {found_name}. "
                "Waiting for acceptance."
            )
        self._refresh_main()
        self._refresh_visible_messages()

    async def handle_incoming(self, msg):
        t = msg.get("type")
        try:
            if t == "ADD_REQUEST":
                return await self._handle_add_request(
                    msg
                )
            if t == "ADD_ACCEPT":
                return await self._handle_add_accept(
                    msg
                )
            if t == "ADD_REJECT":
                return await self._handle_add_reject(
                    msg
                )
            if t == "CHAT_START":
                return await self._handle_chat_start(
                    msg
                )
            if t == "CHAT_ACCEPT":
                return await self._handle_chat_accept(
                    msg
                )
            if t == "CHAT_REJECT":
                return await self._handle_chat_reject(
                    msg
                )
            if t == "CHAT_STOP":
                return await self._handle_chat_stop(
                    msg
                )
            if t == "CLEAR_REQUEST":
                return await self._handle_clear_request(
                    msg
                )
            if t == "CLEAR_ACCEPT":
                return await self._handle_clear_accept(
                    msg
                )
            if t == "CLEAR_REJECT":
                return await self._handle_clear_reject(
                    msg
                )
            if t == "MESSAGE":
                return await self._handle_message(msg)
        except Exception:
            return {"type": "ERROR"}
        return {"type": "ERROR", "reason": "unknown"}

    async def _handle_add_request(self, msg):
        peer_ip = msg.get("_peer_ip")
        now = time.time()
        if peer_ip:
            last = self._add_attempts.get(peer_ip, 0)
            if now - last < ADD_RATE_LIMIT_SECONDS:
                return {
                    "type": "ADD_REJECT",
                    "reason": "rate_limited",
                }
            self._add_attempts[peer_ip] = now
        code = msg.get("code")
        if not self._valid_code(code):
            return {
                "type": "ADD_REJECT",
                "reason": "invalid_code",
            }
        if not verify_totp(self.totp_secret, code):
            return {
                "type": "ADD_REJECT",
                "reason": "invalid_code",
            }
        from_name = msg.get("from_name")
        from_ed = msg.get("from_ed_pub")
        from_x = msg.get("from_x25519_pub")
        from_port = msg.get("from_port")
        timestamp = msg.get("timestamp")
        sig = msg.get("signature")
        if not self._valid_name(from_name):
            return {
                "type": "ADD_REJECT",
                "reason": "missing_name",
            }
        if not self._valid_hex(from_ed, 32):
            return {
                "type": "ADD_REJECT",
                "reason": "missing_ed_key",
            }
        if not self._valid_hex(from_x, 32):
            return {
                "type": "ADD_REJECT",
                "reason": "missing_x_key",
            }
        if not self._valid_timestamp(timestamp):
            return {
                "type": "ADD_REJECT",
                "reason": "stale",
            }
        if not isinstance(from_port, int) or not (
            1 <= from_port <= 65535
        ):
            from_port = None
        try:
            from_pk = ed_public_from_bytes(
                bytes.fromhex(from_ed)
            )
        except Exception:
            return {
                "type": "ADD_REJECT",
                "reason": "bad_key",
            }
        verify_fields = {
            "from_name": from_name,
            "from_ed_pub": from_ed,
            "from_x25519_pub": from_x,
            "from_port": from_port,
            "code": code,
            "timestamp": timestamp,
        }
        if not self._verify_control(
            verify_fields, from_pk, sig
        ):
            return {
                "type": "ADD_REJECT",
                "reason": "bad_signature",
            }
        existing = self.db.get_contact(from_name)
        if existing:
            if existing.get("blocked"):
                return {
                    "type": "ADD_REJECT",
                    "reason": "blocked",
                }
            if existing["ed_public_hex"] != from_ed:
                return {
                    "type": "ADD_REJECT",
                    "reason": "key_mismatch",
                }
        peer = self.discovery.find_by_name(from_name)
        ip = peer["ip"] if peer else peer_ip
        port = (
            peer["tcp_port"] if peer else from_port
        )
        self.db.upsert_contact(
            name=from_name,
            ip=ip,
            port=port,
            ed_public_hex=from_ed,
            x25519_public_hex=from_x,
        )
        resp_fields = {
            "to_name": self.user_name,
            "to_ed_pub": ed_public_to_bytes(
                self.ed_public
            ).hex(),
            "to_x25519_pub": x25519_public_to_bytes(
                self.x25519_public
            ).hex(),
            "timestamp": _now_ms(),
        }
        resp_sig = self._sign_control(resp_fields)
        if existing is None:
            self.db.set_contact_state(
                from_name, pending=2
            )
            self._refresh_main()
            self.notify(
                f"{from_name} wants to add you. "
                "Press Y to accept, X to reject."
            )
            return {
                "type": "ADD_PENDING",
                **resp_fields,
                "signature": resp_sig,
            }
        if existing.get("pending") == 0:
            return {
                "type": "ADD_ACCEPT",
                **resp_fields,
                "signature": resp_sig,
            }
        if existing.get("pending") == 1:
            self.db.set_contact_state(
                from_name, pending=0
            )
            self._refresh_main()
            self.notify(
                f"Mutual add completed with {from_name}."
            )
            return {
                "type": "ADD_ACCEPT",
                **resp_fields,
                "signature": resp_sig,
            }
        self._refresh_main()
        return {
            "type": "ADD_PENDING",
            **resp_fields,
            "signature": resp_sig,
        }

    async def _handle_add_accept(self, msg):
        from_name = msg.get("from_name")
        from_ed = msg.get("from_ed_pub")
        from_x = msg.get("from_x25519_pub")
        timestamp = msg.get("timestamp")
        sig = msg.get("signature")
        if not self._valid_name(from_name):
            return {"type": "OK"}
        if not self._valid_hex(from_ed, 32):
            return {"type": "OK"}
        if not self._valid_hex(from_x, 32):
            return {"type": "OK"}
        if not self._valid_timestamp(timestamp):
            return {"type": "OK"}
        contact = self.db.get_contact(from_name)
        if not contact:
            return {"type": "OK"}
        if contact["ed_public_hex"] != from_ed:
            self.notify(
                f"Rejected add-accept from {from_name}: "
                "key mismatch.",
                severity="error",
            )
            return {"type": "OK"}
        try:
            from_pk = ed_public_from_bytes(
                bytes.fromhex(from_ed)
            )
        except Exception:
            return {"type": "OK"}
        verify_fields = {
            "from_name": from_name,
            "from_ed_pub": from_ed,
            "from_x25519_pub": from_x,
            "timestamp": timestamp,
        }
        if not self._verify_control(
            verify_fields, from_pk, sig
        ):
            return {"type": "OK"}
        if contact.get("pending") in (1, 2):
            self.db.set_contact_state(
                from_name,
                pending=0,
                x25519_public_hex=from_x,
            )
            self._refresh_main()
            self.notify(
                f"{from_name} accepted your add request."
            )
        return {"type": "OK"}

    async def _handle_add_reject(self, msg):
        from_name = msg.get("from_name")
        if not self._valid_name(from_name):
            return {"type": "OK"}
        contact = self.db.get_contact(from_name)
        if contact and contact.get("pending") == 1:
            self.db.delete_contact(from_name)
            self._refresh_main()
            self._refresh_visible_messages()
            self.notify(
                f"{from_name} rejected your add request."
            )
        return {"type": "OK"}

    async def _handle_chat_start(self, msg):
        from_name = msg.get("from_name")
        if not self._valid_name(from_name):
            return {
                "type": "CHAT_REJECT",
                "reason": "invalid",
            }
        contact = self.db.get_contact(from_name)
        if not contact:
            return {
                "type": "CHAT_REJECT",
                "reason": "not_contact",
            }
        if contact.get("blocked"):
            return {
                "type": "CHAT_REJECT",
                "reason": "blocked",
            }
        if contact.get("pending") != 0:
            return {
                "type": "CHAT_REJECT",
                "reason": "pending",
            }
        if not contact.get("x25519_public_hex"):
            return {
                "type": "CHAT_REJECT",
                "reason": "legacy_contact",
            }
        peer_ip = msg.get("_peer_ip")
        if peer_ip and peer_ip != contact.get("ip"):
            self.db.set_contact_state(
                from_name, ip=peer_ip
            )
        if contact.get("chat_started"):
            return {"type": "CHAT_PENDING"}
        self.db.set_contact_state(
            from_name, incoming_request=1
        )
        self._refresh_main()
        self.notify(
            f"{from_name} wants to chat. "
            "Press Y to accept."
        )
        return {"type": "CHAT_PENDING"}

    async def _handle_chat_accept(self, msg):
        from_name = msg.get("from_name")
        if not self._valid_name(from_name):
            return {"type": "OK"}
        contact = self.db.get_contact(from_name)
        if not contact:
            return {"type": "OK"}
        self.db.set_contact_state(
            from_name,
            chat_started=1,
            incoming_request=0,
        )
        self._refresh_main()
        self.notify(f"Chat started with {from_name}.")
        return {"type": "OK"}

    async def _handle_chat_reject(self, msg):
        from_name = msg.get("from_name")
        if self._valid_name(from_name):
            self.notify(
                f"{from_name} rejected your chat request."
            )
        return {"type": "OK"}

    async def _handle_chat_stop(self, msg):
        from_name = msg.get("from_name")
        if not self._valid_name(from_name):
            return {"type": "OK"}
        contact = self.db.get_contact(from_name)
        if not contact:
            return {"type": "OK"}
        self.db.set_contact_state(
            from_name,
            chat_started=0,
            incoming_request=0,
        )
        self._refresh_main()
        self.notify(f"{from_name} stopped the chat.")
        return {"type": "OK"}

    async def _handle_clear_request(self, msg):
        from_name = msg.get("from_name")
        if not self._valid_name(from_name):
            return {
                "type": "CLEAR_REJECT",
                "reason": "invalid",
            }
        contact = self.db.get_contact(from_name)
        if not contact:
            return {
                "type": "CLEAR_REJECT",
                "reason": "not_contact",
            }
        if contact.get("blocked"):
            return {
                "type": "CLEAR_REJECT",
                "reason": "blocked",
            }
        if contact.get("pending") != 0:
            return {
                "type": "CLEAR_REJECT",
                "reason": "pending",
            }
        self.db.set_contact_state(
            from_name, clear_pending=1
        )
        self._refresh_main()
        self.notify(
            f"{from_name} wants to clear the "
            "conversation. Press Y to accept, X to "
            "reject."
        )
        return {"type": "CLEAR_PENDING"}

    async def _handle_clear_accept(self, msg):
        from_name = msg.get("from_name")
        if not self._valid_name(from_name):
            return {"type": "OK"}
        contact = self.db.get_contact(from_name)
        if not contact:
            return {"type": "OK"}
        self.db.clear_messages(from_name)
        self.db.set_contact_state(
            from_name, clear_pending=0
        )
        self._refresh_main()
        self._refresh_visible_messages()
        self.notify(
            f"{from_name} accepted. Conversation "
            "cleared."
        )
        return {"type": "OK"}

    async def _handle_clear_reject(self, msg):
        from_name = msg.get("from_name")
        if self._valid_name(from_name):
            self.notify(
                f"{from_name} declined the clear "
                "request."
            )
        return {"type": "OK"}

    async def _handle_message(self, msg):
        peer_ip = msg.get("_peer_ip")
        now = time.time()
        if peer_ip:
            last = self._msg_attempts.get(peer_ip, 0)
            if now - last < MSG_RATE_LIMIT_SECONDS:
                return {"type": "ERROR"}
            self._msg_attempts[peer_ip] = now
        from_name = msg.get("from_name")
        if not self._valid_name(from_name):
            return {"type": "ERROR"}
        contact = self.db.get_contact(from_name)
        if (
            not contact
            or contact.get("blocked")
            or not contact.get("chat_started")
            or contact.get("pending") != 0
            or not contact.get("x25519_public_hex")
        ):
            return {"type": "ERROR"}
        counter = msg.get("counter")
        if (
            not isinstance(counter, int)
            or counter <= 0
            or counter > 2**63 - 1
        ):
            return {"type": "ERROR"}
        try:
            eph_pub_raw = base64.b64decode(
                msg["ephemeral_pub"]
            )
            nonce = base64.b64decode(msg["nonce"])
            ct = base64.b64decode(msg["ciphertext"])
            sig = base64.b64decode(msg["signature"])
        except Exception:
            return {"type": "ERROR"}
        if (
            len(eph_pub_raw) != 32
            or len(nonce) != 12
            or len(ct) < 16
            or len(sig) != 64
        ):
            return {"type": "ERROR"}
        signed_data = (
            from_name.encode("utf-8")
            + counter.to_bytes(8, "big")
            + eph_pub_raw
            + nonce
            + ct
        )
        try:
            ed_pk = ed_public_from_bytes(
                bytes.fromhex(contact["ed_public_hex"])
            )
        except Exception:
            return {"type": "ERROR"}
        if not verify_bytes(ed_pk, sig, signed_data):
            self.db.set_contact_state(
                from_name, blocked=1
            )
            self.notify(
                f"Signature failure from {from_name}. "
                "Contact blocked.",
                severity="error",
            )
            self._refresh_main()
            self._refresh_visible_messages()
            return {"type": "ERROR"}
        if counter <= contact.get(
            "last_counter_in", 0
        ):
            return {"type": "ERROR"}
        try:
            their_x_pub = x25519_public_from_bytes(
                bytes.fromhex(
                    contact["x25519_public_hex"]
                )
            )
        except Exception:
            return {"type": "ERROR"}
        aad = (
            f"{from_name}:{counter}".encode("utf-8")
        )
        try:
            plaintext = pairwise_decrypt(
                self.x25519_private,
                self.x25519_public,
                their_x_pub,
                eph_pub_raw,
                nonce,
                ct,
                aad,
            )
        except Exception:
            self.db.set_contact_state(
                from_name, blocked=1
            )
            self.notify(
                f"Decryption failure from {from_name}. "
                "Contact blocked.",
                severity="error",
            )
            self._refresh_main()
            self._refresh_visible_messages()
            return {"type": "ERROR"}
        text = plaintext.decode(
            "utf-8", errors="replace"
        )
        if len(text) > MAX_MESSAGE_LEN:
            text = text[:MAX_MESSAGE_LEN]
        self.db.add_message(from_name, "in", text)
        self.db.set_contact_state(
            from_name, last_counter_in=counter
        )
        if peer_ip and peer_ip != contact.get("ip"):
            self.db.set_contact_state(
                from_name, ip=peer_ip
            )
        self._refresh_main()
        self._refresh_visible_messages()
        return {"type": "OK"}

    async def start_chat(self, contact_name):
        contact = self.db.get_contact(contact_name)
        if not contact:
            return
        if contact.get("blocked"):
            self.notify(
                "Contact is blocked.", severity="error"
            )
            return
        if contact.get("pending") != 0:
            self.notify(
                "Contact is not accepted yet.",
                severity="error",
            )
            return
        if not contact.get("x25519_public_hex"):
            self.notify(
                "This contact predates pairwise E2EE. "
                "Delete and re-add them.",
                severity="error",
            )
            return
        if contact.get("chat_started"):
            self.notify("Chat is already active.")
            return
        ip, port = self._resolve_peer_address(contact)
        if not ip or not port:
            self.notify(
                "Contact is offline.", severity="error"
            )
            return
        resp = await send_request(
            ip,
            port,
            {
                "type": "CHAT_START",
                "from_name": self.user_name,
            },
        )
        if not resp:
            self.notify(
                "Could not reach contact.",
                severity="error",
            )
            return
        if resp.get("type") == "CHAT_REJECT":
            self.notify(
                f"Rejected: "
                f"{resp.get('reason', 'unknown')}",
                severity="error",
            )
            return
        self.db.set_contact_state(
            contact_name, ip=ip, port=port
        )
        self.notify(
            f"Chat request sent to {contact_name}."
        )

    async def accept_contact(self, contact_name):
        contact = self.db.get_contact(contact_name)
        if not contact or contact.get("pending") != 2:
            return
        if not contact.get("x25519_public_hex"):
            self.notify(
                "Cannot accept: missing peer key.",
                severity="error",
            )
            return
        ip, port = self._resolve_peer_address(contact)
        if not ip or not port:
            self.notify(
                "Cannot reach contact.", severity="error"
            )
            return
        fields = {
            "from_name": self.user_name,
            "from_ed_pub": ed_public_to_bytes(
                self.ed_public
            ).hex(),
            "from_x25519_pub": x25519_public_to_bytes(
                self.x25519_public
            ).hex(),
            "timestamp": _now_ms(),
        }
        payload = {
            "type": "ADD_ACCEPT",
            **fields,
            "signature": self._sign_control(fields),
        }
        resp = await send_request(ip, port, payload)
        if not resp:
            self.notify(
                "Could not reach contact.",
                severity="error",
            )
            return
        self.db.set_contact_state(
            contact_name, pending=0, ip=ip, port=port
        )
        self._refresh_main()
        self.notify(f"Accepted {contact_name}.")

    async def reject_contact(self, contact_name):
        contact = self.db.get_contact(contact_name)
        if not contact or contact.get("pending") != 2:
            return
        ip, port = self._resolve_peer_address(contact)
        if ip and port:
            await send_request(
                ip,
                port,
                {
                    "type": "ADD_REJECT",
                    "from_name": self.user_name,
                },
            )
        self.db.delete_contact(contact_name)
        self._refresh_main()
        self._refresh_visible_messages()
        self.notify(f"Rejected {contact_name}.")

    async def accept_chat(self, contact_name):
        contact = self.db.get_contact(contact_name)
        if not contact:
            return
        if not contact.get("incoming_request"):
            self.notify(
                "No pending chat request.",
                severity="error",
            )
            return
        ip, port = self._resolve_peer_address(contact)
        if not ip or not port:
            self.notify(
                "Contact is offline.", severity="error"
            )
            return
        resp = await send_request(
            ip,
            port,
            {
                "type": "CHAT_ACCEPT",
                "from_name": self.user_name,
            },
        )
        if not resp:
            self.notify(
                "Could not reach contact.",
                severity="error",
            )
            return
        self.db.set_contact_state(
            contact_name,
            chat_started=1,
            incoming_request=0,
            ip=ip,
            port=port,
        )
        self._refresh_main()
        self.notify(
            f"Chat accepted with {contact_name}."
        )

    async def reject_chat(self, contact_name):
        contact = self.db.get_contact(contact_name)
        if not contact or not contact.get(
            "incoming_request"
        ):
            return
        ip, port = self._resolve_peer_address(contact)
        if ip and port:
            await send_request(
                ip,
                port,
                {
                    "type": "CHAT_REJECT",
                    "from_name": self.user_name,
                },
            )
        self.db.set_contact_state(
            contact_name, incoming_request=0
        )
        self._refresh_main()
        self.notify(
            f"Chat request from {contact_name} rejected."
        )

    async def accept_clear(self, contact_name):
        contact = self.db.get_contact(contact_name)
        if not contact or not contact.get(
            "clear_pending"
        ):
            return
        ip, port = self._resolve_peer_address(contact)
        if not ip or not port:
            self.notify(
                "Contact is offline.", severity="error"
            )
            return
        resp = await send_request(
            ip,
            port,
            {
                "type": "CLEAR_ACCEPT",
                "from_name": self.user_name,
            },
        )
        if not resp:
            self.notify(
                "Could not reach contact.",
                severity="error",
            )
            return
        self.db.clear_messages(contact_name)
        self.db.set_contact_state(
            contact_name, clear_pending=0
        )
        self._refresh_main()
        self._refresh_visible_messages()
        self.notify(
            f"Conversation with {contact_name} cleared."
        )

    async def reject_clear(self, contact_name):
        contact = self.db.get_contact(contact_name)
        if not contact or not contact.get(
            "clear_pending"
        ):
            return
        ip, port = self._resolve_peer_address(contact)
        if ip and port:
            await send_request(
                ip,
                port,
                {
                    "type": "CLEAR_REJECT",
                    "from_name": self.user_name,
                },
            )
        self.db.set_contact_state(
            contact_name, clear_pending=0
        )
        self._refresh_main()
        self.notify(
            f"Declined clear request from {contact_name}."
        )

    async def send_chat_message(
        self, contact_name, text
    ):
        contact = self.db.get_contact(contact_name)
        if not contact:
            return
        if contact.get("blocked"):
            self.notify(
                "Contact is blocked.", severity="error"
            )
            return
        if contact.get("pending") != 0:
            self.notify(
                "Contact is not accepted yet.",
                severity="error",
            )
            return
        if not contact.get("x25519_public_hex"):
            self.notify(
                "This contact predates pairwise E2EE. "
                "Delete and re-add them.",
                severity="error",
            )
            return
        if not contact.get("chat_started"):
            self.notify(
                "Chat not started. Press S to start it.",
                severity="error",
            )
            return
        if "\x00" in text:
            self.notify(
                "Message contains invalid characters.",
                severity="error",
            )
            return
        if len(text) > MAX_MESSAGE_LEN:
            self.notify(
                f"Message too long "
                f"(max {MAX_MESSAGE_LEN}).",
                severity="error",
            )
            return
        ip, port = self._resolve_peer_address(contact)
        if not ip or not port:
            self.notify(
                "Contact is offline.", severity="error"
            )
            return
        try:
            their_x_pub = x25519_public_from_bytes(
                bytes.fromhex(
                    contact["x25519_public_hex"]
                )
            )
        except Exception:
            self.notify(
                "Contact key invalid. Re-add them.",
                severity="error",
            )
            return
        counter = int(contact.get("out_counter", 0)) + 1
        aad = (
            f"{self.user_name}:{counter}".encode(
                "utf-8"
            )
        )
        try:
            (
                eph_pub_raw,
                nonce,
                ct,
            ) = pairwise_encrypt(
                self.x25519_private,
                their_x_pub,
                text.encode("utf-8"),
                aad,
            )
        except Exception:
            self.notify(
                "Encryption failed.", severity="error"
            )
            return
        signed_data = (
            self.user_name.encode("utf-8")
            + counter.to_bytes(8, "big")
            + eph_pub_raw
            + nonce
            + ct
        )
        sig = sign_bytes(self.ed_private, signed_data)
        payload = {
            "type": "MESSAGE",
            "from_name": self.user_name,
            "counter": counter,
            "ephemeral_pub": base64.b64encode(
                eph_pub_raw
            ).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode(
                "ascii"
            ),
            "ciphertext": base64.b64encode(ct).decode(
                "ascii"
            ),
            "signature": base64.b64encode(sig).decode(
                "ascii"
            ),
        }
        resp = await send_request(ip, port, payload)
        if not resp or resp.get("type") != "OK":
            self.notify(
                "Message delivery failed.",
                severity="error",
            )
            return
        self.db.set_contact_state(
            contact_name, out_counter=counter
        )
        self.db.add_message(contact_name, "out", text)
        self._refresh_visible_messages()

    def clear_chat_confirm(self, contact_name):
        self.push_screen(
            ConfirmScreen(
                f"Clear all messages with "
                f"{contact_name} locally?"
            ),
            callback=lambda ok: self._do_clear_chat(
                ok, contact_name
            ),
        )

    def _do_clear_chat(
        self, confirmed, contact_name
    ):
        if confirmed:
            self.db.clear_messages(contact_name)
            self._refresh_visible_messages()
            self.notify(
                f"Cleared chat with {contact_name}."
            )

    def clear_all_confirm(self, contact_name):
        self.push_screen(
            ConfirmScreen(
                f"Ask {contact_name} to clear the "
                "ENTIRE conversation on both sides?\n"
                "Nothing is cleared until they accept."
            ),
            callback=lambda ok: self._do_clear_all(
                ok, contact_name
            ),
        )

    def _do_clear_all(
        self, confirmed, contact_name
    ):
        if confirmed:
            asyncio.create_task(
                self.request_clear_all(contact_name)
            )

    async def request_clear_all(
        self, contact_name
    ):
        contact = self.db.get_contact(contact_name)
        if not contact:
            return
        if contact.get("blocked"):
            self.notify(
                "Contact is blocked.", severity="error"
            )
            return
        if contact.get("pending") != 0:
            self.notify(
                "Contact is not accepted yet.",
                severity="error",
            )
            return
        ip, port = self._resolve_peer_address(contact)
        if not ip or not port:
            self.notify(
                "Contact is offline.", severity="error"
            )
            return
        resp = await send_request(
            ip,
            port,
            {
                "type": "CLEAR_REQUEST",
                "from_name": self.user_name,
            },
        )
        if not resp:
            self.notify(
                "Could not reach contact.",
                severity="error",
            )
            return
        resp_type = resp.get("type")
        if resp_type == "CLEAR_REJECT":
            self.notify(
                f"Rejected: "
                f"{resp.get('reason', 'unknown')}",
                severity="error",
            )
            return
        if resp_type != "CLEAR_PENDING":
            self.notify(
                "Unexpected response.",
                severity="error",
            )
            return
        self.notify(
            f"Clear request sent to {contact_name}. "
            "Waiting for them to accept."
        )

    def stop_chat_confirm(self, contact_name):
        self.push_screen(
            ConfirmScreen(
                f"Stop the chat with {contact_name}?"
            ),
            callback=lambda ok: self._do_stop_chat(
                ok, contact_name
            ),
        )

    def _do_stop_chat(
        self, confirmed, contact_name
    ):
        if confirmed:
            asyncio.create_task(
                self.stop_chat(contact_name)
            )

    async def stop_chat(self, contact_name):
        contact = self.db.get_contact(contact_name)
        if not contact:
            return
        if not contact.get("chat_started"):
            self.notify(
                "No active chat.", severity="error"
            )
            return
        ip, port = self._resolve_peer_address(contact)
        if ip and port:
            await send_request(
                ip,
                port,
                {
                    "type": "CHAT_STOP",
                    "from_name": self.user_name,
                },
            )
        self.db.set_contact_state(
            contact_name,
            chat_started=0,
            incoming_request=0,
        )
        self._refresh_main()
        self.notify(
            f"Chat with {contact_name} stopped."
        )

    def delete_message_confirm(self, message_id):
        self.push_screen(
            ConfirmScreen(
                f"Delete message #{message_id}?"
            ),
            callback=lambda ok: self._do_delete_message(
                ok, message_id
            ),
        )

    def _do_delete_message(
        self, confirmed, message_id
    ):
        if confirmed:
            self.db.delete_message(message_id)
            self._refresh_visible_messages()
            self.notify(
                f"Deleted message #{message_id}."
            )

    def delete_contact_confirm(self, contact_name):
        self.push_screen(
            ConfirmScreen(
                f"Delete contact {contact_name} and "
                "all messages with them?"
            ),
            callback=lambda ok: self._do_delete_contact(
                ok, contact_name
            ),
        )

    def _do_delete_contact(
        self, confirmed, contact_name
    ):
        if confirmed:
            self.db.delete_contact(contact_name)
            screen = self.screen
            if (
                isinstance(screen, MainScreen)
                and screen.current_contact
                == contact_name
            ):
                screen.load_messages_for(None)
            self._refresh_main()
            self._refresh_visible_messages()
            self.notify(
                f"Deleted contact {contact_name}."
            )

    async def perform_reset(self):
        try:
            if self.server:
                await self.server.stop()
        except Exception:
            pass
        if self.broadcast_task:
            try:
                self.broadcast_task.cancel()
            except Exception:
                pass
        try:
            self.db.reset_all()
        except Exception:
            pass
        if isinstance(self.group_key, bytearray):
            try:
                for i in range(len(self.group_key)):
                    self.group_key[i] = 0
            except Exception:
                pass
        if isinstance(self.lookup_key, bytearray):
            try:
                for i in range(len(self.lookup_key)):
                    self.lookup_key[i] = 0
            except Exception:
                pass
        self.group_key = None
        self.lookup_key = None
        self.totp_secret = None
        self.ed_private = None
        self.ed_public = None
        self.x25519_private = None
        self.x25519_public = None
        self.user_name = None
        self.tcp_port = None
        self.server = None
        self.broadcast_task = None
        self._add_attempts = {}
        self._msg_attempts = {}
        while len(self.screen_stack) > 1:
            self.pop_screen()
        screen = self.screen
        if isinstance(screen, StartupScreen):
            screen.refresh_state()
        else:
            self.push_screen(StartupScreen(self.db))
        self.notify("All data wiped.")

    def _refresh_main(self):
        screen = self.screen
        if isinstance(screen, MainScreen):
            screen.refresh_contacts()

    def _refresh_visible_messages(self):
        screen = self.screen
        if (
            isinstance(screen, MainScreen)
            and screen.current_contact
        ):
            screen.load_messages_for(
                screen.current_contact
            )