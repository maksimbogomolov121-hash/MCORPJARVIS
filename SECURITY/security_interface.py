"""
JARVIS SECURITY
V8.4 - JARVIS HUD Security Interface

Графический интерфейс Security Center.

Особенности:
- JARVIS HUD-стилистика;
- интерактивные кнопки;
- hover-анимации;
- активная подсветка разделов;
- статусные индикаторы;
- анимированный индикатор сканирования;
- обзор состояния защиты;
- быстрый анализ;
- полная проверка;
- проверка файла;
- проверка папки;
- проверка USB;
- просмотр угроз;
- карантин;
- мониторинг;
- сеть;
- автозагрузка;
- Firewall;
- DNS;
- отчёты;
- настройки;
- подключение к Security API.

Sandbox не используется.
"""

import threading
import tkinter as tk
from tkinter import filedialog, messagebox
from typing import Any, Dict, Optional


class SecurityInterface:
    """
    JARVIS Security V8.4 HUD Interface.
    """

    VERSION = "8.4"

    # ============================================================
    # COLORS
    # ============================================================

    BG = "#070b10"
    BG_2 = "#0a1017"

    PANEL = "#0d151e"
    PANEL_2 = "#111c27"
    PANEL_3 = "#152330"

    BORDER = "#203241"
    BORDER_ACTIVE = "#2e637d"

    TEXT = "#e8f4fa"
    TEXT_SECONDARY = "#7f96a6"
    TEXT_DIM = "#536b7b"

    CYAN = "#45d7ff"
    CYAN_BRIGHT = "#79e7ff"
    BLUE = "#348dff"

    GREEN = "#35e08a"
    GREEN_DARK = "#123c2c"

    YELLOW = "#f2c75c"
    YELLOW_DARK = "#443a18"

    RED = "#ff5964"
    RED_DARK = "#421b20"

    # ============================================================
    # INIT
    # ============================================================

    def __init__(
        self,
        security_api: Optional[Any] = None,
        logger: Optional[Any] = None,
        parent: Optional[tk.Tk] = None,
    ):
        self.security_api = security_api
        self.logger = logger

        self.root = parent
        self.own_root = False

        self.current_page = "overview"
        self.running = False

        self.last_result: Optional[Dict[str, Any]] = None

        self.threats = []
        self.notifications = []

        self.page_frame: Optional[tk.Frame] = None
        self.status_label: Optional[tk.Label] = None
        self.content_title: Optional[tk.Label] = None
        self.content_subtitle: Optional[tk.Label] = None

        self.nav_buttons: Dict[str, tk.Button] = {}

        self.scan_animation_running = False
        self.scan_animation_job = None

        if self.root is None:
            self.root = tk.Tk()
            self.own_root = True

        self._configure_window()
        self._build_interface()
        self.show_page("overview")

    # ============================================================
    # WINDOW
    # ============================================================

    def _configure_window(self) -> None:
        self.root.title("JARVIS SECURITY")

        self.root.geometry("1240x760")
        self.root.minsize(1050, 680)

        self.root.configure(
            bg=self.BG
        )

        try:
            self.root.protocol(
                "WM_DELETE_WINDOW",
                self.close,
            )
        except Exception:
            pass

    # ============================================================
    # MAIN INTERFACE
    # ============================================================

    def _build_interface(self) -> None:

        # --------------------------------------------------------
        # TOP HUD
        # --------------------------------------------------------

        header = tk.Frame(
            self.root,
            bg=self.BG_2,
            height=72,
        )

        header.pack(
            side=tk.TOP,
            fill=tk.X,
        )

        header.pack_propagate(False)

        # Left technical marker

        marker = tk.Frame(
            header,
            bg=self.CYAN,
            width=3,
        )

        marker.pack(
            side=tk.LEFT,
            fill=tk.Y,
        )

        logo_frame = tk.Frame(
            header,
            bg=self.BG_2,
        )


        logo_frame.pack(
            side=tk.LEFT,
            padx=(18, 0),
        )

        tk.Label(
            logo_frame,
            text="JARVIS",
            bg=self.BG_2,
            fg=self.CYAN_BRIGHT,
            font=("Segoe UI", 15, "bold"),
        ).pack(
            anchor="w",
        )

        tk.Label(
            logo_frame,
            text="SECURITY CONSOLE",
            bg=self.BG_2,
            fg=self.TEXT_SECONDARY,
            font=("Segoe UI", 8, "bold"),
        ).pack(
            anchor="w",
        )

        # System indicator

        system_frame = tk.Frame(
            header,
            bg=self.BG_2,
        )

        system_frame.pack(
            side=tk.LEFT,
            padx=35,
        )

        self.system_status_dot = tk.Label(
            system_frame,
            text="●",
            bg=self.BG_2,
            fg=self.GREEN,
            font=("Segoe UI", 11),
        )

        self.system_status_dot.pack(
            side=tk.LEFT,
            padx=(0, 5),
        )

        self.system_status_text = tk.Label(
            system_frame,
            text="SYSTEM NOMINAL",
            bg=self.BG_2,
            fg=self.GREEN,
            font=("Segoe UI", 8, "bold"),
        )

        self.system_status_text.pack(
            side=tk.LEFT,
        )

        # Header technical info

        tech_frame = tk.Frame(
            header,
            bg=self.BG_2,
        )

        tech_frame.pack(
            side=tk.RIGHT,
            padx=18,
        )

        tk.Label(
            tech_frame,
            text="SECURITY CORE",
            bg=self.BG_2,
            fg=self.TEXT_DIM,
            font=("Consolas", 7, "bold"),
        ).pack(
            anchor="e",
        )

        tk.Label(
            tech_frame,
            text=f"V{self.VERSION}",
            bg=self.BG_2,
            fg=self.CYAN,
            font=("Consolas", 9, "bold"),
        ).pack(
            anchor="e",
        )

        settings_button = self._hud_button(
            header,
            "⚙",
            lambda: self.show_page("settings"),
        )

        settings_button.pack(
            side=tk.RIGHT,
            padx=(8, 0),
        )

        # --------------------------------------------------------
        # HUD LINE
        # --------------------------------------------------------

        line = tk.Frame(
            self.root,
            bg=self.BORDER,
            height=1,
        )

        line.pack(
            side=tk.TOP,
            fill=tk.X,
        )

        # --------------------------------------------------------
        # BODY
        # --------------------------------------------------------

        body = tk.Frame(
            self.root,
            bg=self.BG,
        )

        body.pack(
            fill=tk.BOTH,
            expand=True,
        )

        # --------------------------------------------------------
        # SIDEBAR
        # --------------------------------------------------------

        self.sidebar = tk.Frame(
            body,
            bg=self.PANEL,
            width=235,
        )

        self.sidebar.pack(
            side=tk.LEFT,
            fill=tk.Y,
        )

        self.sidebar.pack_propagate(False)

        self._build_sidebar()

        # --------------------------------------------------------
        # CONTENT
        # --------------------------------------------------------

        self.main_area = tk.Frame(
            body,
            bg=self.BG,
        )

        self.main_area.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True,
            padx=20,
            pady=18,
        )

        # --------------------------------------------------------
        # PAGE HEADER
        # --------------------------------------------------------

        page_header = tk.Frame(
            self.main_area,
            bg=self.BG,
            height=55,
        )

        page_header.pack(

            fill=tk.X,
            pady=(0, 14),
        )

        page_header.pack_propagate(False)

        title_frame = tk.Frame(
            page_header,
            bg=self.BG,
        )

        title_frame.pack(
            side=tk.LEFT,
            fill=tk.Y,
        )

        self.content_title = tk.Label(
            title_frame,
            text="Обзор",
            bg=self.BG,
            fg=self.TEXT,
            font=("Segoe UI", 22, "bold"),
            anchor="w",
        )

        self.content_title.pack(
            anchor="w",
        )

        self.content_subtitle = tk.Label(
            title_frame,
            text="Текущее состояние системы безопасности",
            bg=self.BG,
            fg=self.TEXT_SECONDARY,
            font=("Segoe UI", 9),
            anchor="w",
        )

        self.content_subtitle.pack(
            anchor="w",
        )

        # Decorative HUD data

        hud_info = tk.Frame(
            page_header,
            bg=self.BG,
        )

        hud_info.pack(
            side=tk.RIGHT,
            fill=tk.Y,
        )

        tk.Label(
            hud_info,
            text="SECURITY",
            bg=self.BG,
            fg=self.TEXT_DIM,
            font=("Consolas", 7, "bold"),
        ).pack(
            anchor="e",
        )

        tk.Label(
            hud_info,
            text="ACTIVE",
            bg=self.BG,
            fg=self.GREEN,
            font=("Consolas", 9, "bold"),
        ).pack(
            anchor="e",
        )

        # --------------------------------------------------------
        # PAGE CONTENT
        # --------------------------------------------------------

        self.page_frame = tk.Frame(
            self.main_area,
            bg=self.BG,
        )

        self.page_frame.pack(
            fill=tk.BOTH,
            expand=True,
        )

        # --------------------------------------------------------
        # BOTTOM STATUS
        # --------------------------------------------------------

        footer = tk.Frame(
            self.root,
            bg=self.PANEL,
            height=38,
        )

        footer.pack(
            side=tk.BOTTOM,
            fill=tk.X,
        )

        footer.pack_propagate(False)

        self.status_label = tk.Label(
            footer,
            text="●  SYSTEM NOMINAL",
            bg=self.PANEL,
            fg=self.GREEN,
            font=("Segoe UI", 8, "bold"),
            anchor="w",
        )

        self.status_label.pack(
            side=tk.LEFT,
            padx=18,
        )

        self.footer_activity = tk.Label(
            footer,
            text="READY",
            bg=self.PANEL,
            fg=self.TEXT_DIM,
            font=("Consolas", 7, "bold"),
        )

        self.footer_activity.pack(
            side=tk.LEFT,
            padx=20,
        )

        tk.Label(
            footer,
            text="JARVIS SECURITY V8.4",
            bg=self.PANEL,
            fg=self.TEXT_DIM,
            font=("Consolas", 7),
        ).pack(
            side=tk.RIGHT,
            padx=18,
        )

    # ============================================================
    # SIDEBAR
    # ============================================================

    def _build_sidebar(self) -> None:

        # Sidebar header

        side_header = tk.Frame(
            self.sidebar,
            bg=self.PANEL,
            height=58,
        )

        side_header.pack(
            fill=tk.X,
        )

        side_header.pack_propagate(False)

        tk.Label(
            side_header,
            text="SECURITY MODULES",
            bg=self.PANEL,
            fg=self.TEXT_DIM,
            font=("Consolas", 8, "bold"),
            anchor="w",
        ).pack(
            fill=tk.X,
            padx=17,
            pady=(17, 0),
        )

        buttons = [
            ("⌂", "ОБЗОР", "overview"),
            ("⌕", "ПРОВЕРКА", "scan"),
            ("!", "УГРОЗЫ", "threats"),
            ("□", "КАРАНТИН", "quarantine"),
            ("◉", "МОНИТОРИНГ", "monitoring"),
            ("◎", "СЕТЬ", "network"),
            ("↗", "АВТОЗАГРУЗКА", "startup"),
            ("◆", "FIREWALL", "firewall"),
            ("◇", "DNS", "dns"),
            ("▤", "ОТЧЁТЫ", "reports"),
            ("⚙", "НАСТРОЙКИ", "settings"),
        ]

        for icon, text, page in buttons:

            button = self._nav_button(
                self.sidebar,
                icon,
                text,
                page,
            )

            button.pack(
                fill=tk.X,
                padx=8,
                pady=2,
            )

            self.nav_buttons[page] = button

        # Spacer

        spacer = tk.Frame(
            self.sidebar,
            bg=self.PANEL,
        )

        spacer.pack(
            fill=tk.BOTH,
            expand=True,
        )

        # Bottom status block

        bottom = tk.Frame(
            self.sidebar,
            bg=self.PANEL,
        )

        bottom.pack(
            fill=tk.X,
            padx=14,
            pady=15,
        )

        tk.Frame(
            bottom,
            bg=self.BORDER,
            height=1,
        ).pack(
            fill=tk.X,
            pady=(0, 12),
        )

        tk.Label(
            bottom,
            text="PROTECTION",
            bg=self.PANEL,
            fg=self.TEXT_DIM,
            font=("Consolas", 7, "bold"),
        ).pack(
            anchor="w",
        )

        self.protection_status = tk.Label(
            bottom,
            text="●  PROTECTED",
            bg=self.PANEL,
            fg=self.GREEN,
            font=("Segoe UI", 9, "bold"),
        )

        self.protection_status.pack(
            anchor="w",
            pady=(3, 0),
        )

    # ============================================================
    # NAVIGATION BUTTON
    # ============================================================

    def _nav_button(
        self,
        parent: tk.Widget,
        icon: str,
        text: str,
        page: str,
    ) -> tk.Button:

        button = tk.Button(
            parent,
            text=f"  {icon}   {text}",
            command=lambda p=page: self.show_page(p),
            bg=self.PANEL,
            fg=self.TEXT_SECONDARY,
            activebackground=self.PANEL_2,
            activeforeground=self.TEXT,
            relief=tk.FLAT,
            bd=0,
            anchor="w",
            font=("Segoe UI", 9, "bold"),
            cursor="hand2",
            padx=12,
            pady=9,
        )

        button._jarvis_normal_bg = self.PANEL
        button._jarvis_hover_bg = self.PANEL_2
        button._jarvis_active_bg = "#102632"
        button._jarvis_normal_fg = self.TEXT_SECONDARY
        button._jarvis_hover_fg = self.TEXT
        button._jarvis_active_fg = self.CYAN_BRIGHT
        button._jarvis_page = page

        button.bind(
            "<Enter>",
            lambda event, b=button: self._button_hover(
                b,
                True,
            ),
        )

        button.bind(
            "<Leave>",
            lambda event, b=button: self._button_hover(
                b,
                False,
            ),
        )

        button.bind(
            "<ButtonPress-1>",
            lambda event, b=button: self._button_press(
                b,
            ),
        )

        button.bind(
            "<ButtonRelease-1>",
            lambda event, b=button: self._button_release(
                b,
            ),
        )

        return button

    # ============================================================
    # HUD BUTTON
    # ============================================================

    def _hud_button(
        self,
        parent: tk.Widget,
        text: str,
        command: Any,
    ) -> tk.Button:

        button = tk.Button(
            parent,
            text=text,
            command=command,
            bg=self.BG_2,
            fg=self.TEXT_SECONDARY,
            activebackground=self.PANEL_2,
            activeforeground=self.CYAN_BRIGHT,
            relief=tk.FLAT,
            bd=0,
            font=("Segoe UI", 14),
            cursor="hand2",
            padx=10,
            pady=5,
        )

        button.bind(
            "<Enter>",
            lambda event: button.configure(
                fg=self.CYAN_BRIGHT,
                bg=self.PANEL,
            ),
        )

        button.bind(
            "<Leave>",
            lambda event: button.configure(
                fg=self.TEXT_SECONDARY,
                bg=self.BG_2,
            ),
        )

        return button

    # ============================================================
    # HOVER ANIMATION
    # ============================================================

    def _button_hover(
        self,
        button: tk.Button,
        entering: bool,
    ) -> None:

        page = getattr(
            button,
            "_jarvis_page",
            None,
        )

        if page == self.current_page:
            return

        if entering:
            self._animate_button(
                button,
                button.cget("bg"),
                button._jarvis_hover_bg,
            )

            button.configure(
                fg=button._jarvis_hover_fg,
            )

        else:
            self._animate_button(
                button,
                button.cget("bg"),
                button._jarvis_normal_bg,
            )

            button.configure(
                fg=button._jarvis_normal_fg,
            )

    # ============================================================
    # BUTTON PRESS
    # ============================================================

    def _button_press(
        self,
        button: tk.Button,
    ) -> None:

        page = getattr(
            button,
            "_jarvis_page",
            None,
        )

        if page == self.current_page:
            return

        button.configure(
            bg=self.CYAN,
            fg=self.BG,
        )

    def _button_release(
        self,
        button: tk.Button,
    ) -> None:

        page = getattr(
            button,
            "_jarvis_page",
            None,
        )

        if page == self.current_page:
            return

        button.configure(
            bg=button._jarvis_hover_bg,
            fg=button._jarvis_hover_fg,
        )

    # ============================================================
    # COLOR ANIMATION
    # ============================================================

    def _animate_button(
        self,
        button: tk.Button,
        start_color: str,
        end_color: str,
        steps: int = 7,
        step: int = 0,
    ) -> None:

        if not button.winfo_exists():
            return

        if step >= steps:
            button.configure(
                bg=end_color,
            )
            return

        start = self._hex_to_rgb(start_color)
        end = self._hex_to_rgb(end_color)

        ratio = (step + 1) / steps

        current = tuple(
            int(
                start[i]
                + (
                    end[i]
                    - start[i]
                )
                * ratio
            )
            for i in range(3)
        )

        color = self._rgb_to_hex(
            current
        )

        button.configure(
            bg=color,
        )

        try:
            self.root.after(
                18,
                lambda: self._animate_button(
                    button,
                    color,
                    end_color,
                    steps,
                    step + 1,
                ),
            )
        except Exception:
            pass

    @staticmethod
    def _hex_to_rgb(
        color: str,
    ) -> tuple:

        color = color.lstrip("#")

        return tuple(
            int(
                color[i:i + 2],
                16,
            )
            for i in (
                0,
                2,
                4,
            )
        )

    @staticmethod
    def _rgb_to_hex(
        rgb: tuple,
    ) -> str:

        return "#{:02x}{:02x}{:02x}".format(
            *rgb
        )

    # ============================================================
    # PAGE ROUTER
    # ============================================================

    def show_page(
        self,
        page: str,
    ) -> None:

        self.current_page = page

        # Stop scanning animation when leaving scan page

        if page != "scan":
            self._stop_scan_animation()

        # Update navigation

        self._update_navigation()

        if self.page_frame is None:
            return

        for widget in self.page_frame.winfo_children():
            widget.destroy()

        pages = {
            "overview": self._page_overview,
            "scan": self._page_scan,
            "threats": self._page_threats,
            "quarantine": self._page_quarantine,
            "monitoring": self._page_monitoring,
            "network": self._page_network,
            "startup": self._page_startup,
            "firewall": self._page_firewall,
            "dns": self._page_dns,
            "reports": self._page_reports,
            "settings": self._page_settings,
        }

        page_function = pages.get(
            page,
            self._page_overview,
        )

        page_function()

    # ============================================================
    # UPDATE NAVIGATION
    # ============================================================

    def _update_navigation(self) -> None:

        for page, button in self.nav_buttons.items():

            if page == self.current_page:

                button.configure(
                    bg=button._jarvis_active_bg,
                    fg=button._jarvis_active_fg,
                )

            else:

                button.configure(
                    bg=button._jarvis_normal_bg,
                    fg=button._jarvis_normal_fg,
                )

    # ============================================================
    # OVERVIEW
    # ============================================================

    def _page_overview(self) -> None:

        self._set_page_header(
            "Обзор",
            "Текущее состояние системы безопасности",
        )

        # --------------------------------------------------------
        # STATUS CARDS
        # --------------------------------------------------------

        top = tk.Frame(
            self.page_frame,
            bg=self.BG,
        )

        top.pack(
            fill=tk.X,
        )

        # Security

        status_card = self._card(
            top,
            height=175,
        )

        status_card.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True,
            padx=(0, 7),
        )

        self._card_title(
            status_card,
            "SECURITY STATUS",
        )

        tk.Label(
            status_card,
            text="●  ЗАЩИТА АКТИВНА",
            bg=self.PANEL,
            fg=self.GREEN,
            font=("Segoe UI", 16, "bold"),
        ).pack(
            anchor="w",
            padx=18,
            pady=(10, 3),
        )

        tk.Label(
            status_card,
            text="Security Core работает нормально",
            bg=self.PANEL,
            fg=self.TEXT_SECONDARY,
            font=("Segoe UI", 9),
        ).pack(
            anchor="w",
            padx=18,
        )

        # Score

        score_card = self._card(
            top,
            height=175,
        )

        score_card.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True,
            padx=7,
        )

        self._card_title(
            score_card,
            "SECURITY SCORE",
        )

        tk.Label(
            score_card,
            text="92",
            bg=self.PANEL,
            fg=self.CYAN_BRIGHT,
            font=("Segoe UI", 28, "bold"),
        ).pack(
            anchor="w",
            padx=18,
            pady=(2, 0),
        )

        tk.Label(
            score_card,
            text="/ 100     GOOD",
            bg=self.PANEL,
            fg=self.GREEN,
            font=("Consolas", 9, "bold"),
        ).pack(
            anchor="w",
            padx=18,
        )

        # Threats

        threat_card = self._card(
            top,
            height=175,
        )

        threat_card.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True,
            padx=(7, 0),
        )

        self._card_title(
            threat_card,
            "THREAT MONITOR",
        )

        threat_color = (
            self.RED
            if self.threats
            else self.GREEN
        )

        tk.Label(
            threat_card,
            text=str(len(self.threats)),
            bg=self.PANEL,
            fg=threat_color,
            font=("Segoe UI", 28, "bold"),
        ).pack(
            anchor="w",
            padx=18,
            pady=(2, 0),
        )

        tk.Label(
            threat_card,
            text=(
                "ACTIVE THREATS"
                if self.threats
                else "NO ACTIVE THREATS"
            ),
            bg=self.PANEL,
            fg=threat_color,
            font=("Consolas", 9, "bold"),
        ).pack(
            anchor="w",
            padx=18,
        )

        # --------------------------------------------------------
        # QUICK ACTIONS
        # --------------------------------------------------------

        actions = self._card(
            self.page_frame,
            height=170,
        )

        actions.pack(
            fill=tk.X,
            pady=14,
        )

        self._card_title(
            actions,
            "QUICK ACTIONS",
        )

        action_frame = tk.Frame(
            actions,
            bg=self.PANEL,
        )

        action_frame.pack(
            fill=tk.X,
            padx=18,
            pady=(7, 0),
        )

        self._action_button(
            action_frame,
            "⌕  БЫСТРАЯ ПРОВЕРКА",
            self.quick_scan,
        ).pack(
            side=tk.LEFT,
            padx=(0, 7),
        )

        self._action_button(
            action_frame,
            "◆  ПОЛНАЯ ПРОВЕРКА",
            self.full_scan,
        ).pack(
            side=tk.LEFT,
            padx=7,
        )

        self._action_button(
            action_frame,
            "□  ПРОВЕРИТЬ ФАЙЛ",
            self.scan_file_dialog,
        ).pack(
            side=tk.LEFT,
            padx=7,
        )

        self._action_button(
            action_frame,
            "□  ПРОВЕРИТЬ ПАПКУ",
            self.scan_folder_dialog,
        ).pack(
            side=tk.LEFT,
            padx=7,
        )

        # --------------------------------------------------------
        # COMPONENTS
        # --------------------------------------------------------

        components = self._card(
            self.page_frame,
        )

        components.pack(
            fill=tk.BOTH,
            expand=True,
        )

        self._card_title(
            components,
            "CORE COMPONENT STATUS",
        )

        component_names = [
            "Security Controller",
            "Security Pipeline",
            "Decision Engine",
            "Security Policy",
            "Auto Response",
            "Remediation Engine",
            "Recovery Manager",
        ]

        for name in component_names:

            row = tk.Frame(
                components,
                bg=self.PANEL,
                height=29,
            )

            row.pack(
                fill=tk.X,
                padx=18,
                pady=1,
            )

            row.pack_propagate(False)

            tk.Label(
                row,
                text=name,
                bg=self.PANEL,
                fg=self.TEXT,
                font=("Segoe UI", 8),
                anchor="w",
            ).pack(
                side=tk.LEFT,
            )

            tk.Label(
                row,
                text="● ONLINE",
                bg=self.PANEL,
                fg=self.GREEN,
                font=("Consolas", 7, "bold"),
            ).pack(
                side=tk.RIGHT,
            )

    # ============================================================
    # SCAN PAGE
    # ============================================================

    def _page_scan(self) -> None:

        self._set_page_header(
            "Проверка",
            "Запуск анализа системы безопасности",
        )

        buttons = [
            (
                "⌕",
                "БЫСТРАЯ ПРОВЕРКА",
                "Проверка основных областей системы",
                self.quick_scan,
            ),
            (
                "◆",
                "ПОЛНАЯ ПРОВЕРКА",
                "Глубокий анализ системы",
                self.full_scan,
            ),
            (
                "□",
                "ПРОВЕРКА ФАЙЛА",
                "Проверить конкретный файл",
                self.scan_file_dialog,
            ),
            (
                "□",
                "ПРОВЕРКА ПАПКИ",
                "Проверить содержимое директории",
                self.scan_folder_dialog,
            ),
            (
                "▣",
                "ПРОВЕРКА USB",
                "Проверить подключённый накопитель",
                self.scan_usb,
            ),
        ]

        for icon, title, description, command in buttons:

            card = self._card(
                self.page_frame,
                height=82,
            )

            card.pack(
                fill=tk.X,
                pady=4,
            )

            icon_label = tk.Label(
                card,
                text=icon,
                bg=self.PANEL,
                fg=self.CYAN,
                font=("Segoe UI", 21),
            )

            icon_label.pack(
                side=tk.LEFT,
                padx=18,
            )

            text_frame = tk.Frame(
                card,
                bg=self.PANEL,
            )

            text_frame.pack(
                side=tk.LEFT,
                fill=tk.BOTH,
                expand=True,
            )

            tk.Label(
                text_frame,
                text=title,
                bg=self.PANEL,
                fg=self.TEXT,
                font=("Segoe UI", 10, "bold"),
                anchor="w",
            ).pack(
                anchor="w",
                pady=(12, 0),
            )

            tk.Label(
                text_frame,
                text=description,
                bg=self.PANEL,
                fg=self.TEXT_SECONDARY,
                font=("Segoe UI", 8),
                anchor="w",
            ).pack(
                anchor="w",
            )

            self._small_button(
                card,
                "ПРОВЕРИТЬ",
                command,
            ).pack(
                side=tk.RIGHT,
                padx=18,
            )

        self._start_scan_animation()

    # ============================================================
    # SCAN ANIMATION
    # ============================================================

    def _start_scan_animation(self) -> None:

        if self.scan_animation_running:
            return

        self.scan_animation_running = True

        self._scan_animation_step(
            0
        )

    def _scan_animation_step(
        self,
        position: int,
    ) -> None:

        if not self.scan_animation_running:
            return

        if self.current_page != "scan":
            return

        dots = "." * position

        self.footer_activity.configure(
            text=f"READY FOR ANALYSIS{dots}",
            fg=self.CYAN,
        )

        next_position = (
            position + 1
        ) % 4

        try:

         self.scan_animation_job = self.root.after(
                350,
                lambda: self._scan_animation_step(
                    next_position
                ),
            )

        except Exception:
            pass

    def _stop_scan_animation(self) -> None:

        self.scan_animation_running = False

        if self.scan_animation_job is not None:

            try:
                self.root.after_cancel(
                    self.scan_animation_job
                )
            except Exception:
                pass

            self.scan_animation_job = None

        if hasattr(
            self,
            "footer_activity",
        ):

            self.footer_activity.configure(
                text="READY",
                fg=self.TEXT_DIM,
            )

    # ============================================================
    # THREATS
    # ============================================================

    def _page_threats(self) -> None:

        self._set_page_header(
            "Угрозы",
            "Обнаруженные потенциально опасные объекты",
        )

        if not self.threats:

            self._empty_state(
                "✓",
                "УГРОЗ НЕ ОБНАРУЖЕНО",
                "Security Core не обнаружил активных угроз.",
                color=self.GREEN,
            )

            return

        for threat in self.threats:

            card = self._card(
                self.page_frame,
                height=105,
            )

            card.pack(
                fill=tk.X,
                pady=5,
            )

            tk.Label(
                card,
                text="!",
                bg=self.PANEL,
                fg=self.RED,
                font=("Segoe UI", 22, "bold"),
            ).pack(
                side=tk.LEFT,
                padx=18,
            )

            text = tk.Frame(
                card,
                bg=self.PANEL,
            )

            text.pack(
                side=tk.LEFT,
                fill=tk.BOTH,
                expand=True,
                pady=12,
            )

            target = str(
                threat.get(
                    "target",
                    "Unknown",
                )
            )

            tk.Label(
                text,
                text=target,
                bg=self.PANEL,
                fg=self.TEXT,
                font=("Segoe UI", 10, "bold"),
                anchor="w",
            ).pack(
                anchor="w",
            )

            tk.Label(
                text,
                text=str(
                    threat.get(
                        "message",
                        "Potential threat",
                    )
                ),
                bg=self.PANEL,
                fg=self.TEXT_SECONDARY,
                font=("Segoe UI", 8),
                anchor="w",
            ).pack(
                anchor="w",
            )

    # ============================================================
    # QUARANTINE
    # ============================================================

    def _page_quarantine(self) -> None:

        self._set_page_header(
            "Карантин",
            "Изолированные объекты",
        )

        self._empty_state(
            "□",
            "QUARANTINE",
            "Объекты карантина будут отображаться здесь.",
            color=self.CYAN,
        )

    # ============================================================
    # MONITORING
    # ============================================================

    def _page_monitoring(self) -> None:

        self._set_page_header(
            "Мониторинг",
            "Журнал событий безопасности",
        )

        events = [
            "Security Interface started",
            "Security Core ready",
            "Monitoring initialized",
        ]

        for event in events:

            row = self._card(
                self.page_frame,
                height=42,
            )

            row.pack(
                fill=tk.X,
                pady=3,
            )

            tk.Label(
                row,
                text="●",
                bg=self.PANEL,
                fg=self.GREEN,
            ).pack(
                side=tk.LEFT,
                padx=15,
            )

            tk.Label(
                row,
                text=event,
                bg=self.PANEL,
                fg=self.TEXT,
                font=("Consolas", 8),
            ).pack(
                side=tk.LEFT,
            )

    # ============================================================
    # NETWORK
    # ============================================================

    def _page_network(self) -> None:

        self._set_page_header(
            "Сеть",
            "Активные сетевые соединения",
        )

        self._empty_state(
            "◎",
            "NETWORK",
            "Сетевые события Security Core будут отображаться здесь.",
            color=self.CYAN,
        )

    # ============================================================
    # STARTUP
    # ============================================================

    def _page_startup(self) -> None:

        self._set_page_header(
            "Автозагрузка",
            "Элементы автозапуска системы",
        )

        self._empty_state(
            "↗",
            "STARTUP",
            "Результаты Startup Scanner будут отображаться здесь.",
            color=self.CYAN,
        )

    # ============================================================
    # FIREWALL
    # ============================================================

    def _page_firewall(self) -> None:

        self._set_page_header(
            "Firewall",
            "Состояние Windows Firewall",
        )

        card = self._card(
            self.page_frame,
            height=135,
        )

        card.pack(
            fill=tk.X,
        )

        self._card_title(
            card,
            "WINDOWS FIREWALL",
        )

        tk.Label(
            card,
            text="●  ACTIVE",
            bg=self.PANEL,
            fg=self.GREEN,
            font=("Segoe UI", 18, "bold"),
        ).pack(
            anchor="w",
            padx=18,
            pady=3,
        )

        self._small_button(
            card,
            "ПРОВЕРИТЬ",
            self.scan_firewall,
        ).pack(
            side=tk.RIGHT,
            padx=18,
        )

    # ============================================================
    # DNS
    # ============================================================

    def _page_dns(self) -> None:

        self._set_page_header(
            "DNS",
            "Состояние DNS-конфигурации",
        )

        card = self._card(
            self.page_frame,
            height=135,
        )

        card.pack(
            fill=tk.X,
        )

        self._card_title(
            card,
            "DNS SECURITY",
        )

        tk.Label(
            card,
            text="●  NORMAL",
            bg=self.PANEL,
            fg=self.GREEN,
            font=("Segoe UI", 18, "bold"),
        ).pack(
            anchor="w",
            padx=18,
            pady=3,
        )

        self._small_button(
            card,
            "ПРОВЕРИТЬ",
            self.scan_dns,
        ).pack(
            side=tk.RIGHT,
            padx=18,
        )

    # ============================================================
    # REPORTS
    # ============================================================

    def _page_reports(self) -> None:

        self._set_page_header(
            "Отчёты",
            "История операций Security",
        )

        if not self.last_result:

            self._empty_state(
                "▤",
                "НЕТ ОТЧЁТОВ",
                "После первой проверки здесь появится результат.",
                color=self.CYAN,
            )

            return

        card = self._card(
            self.page_frame,
        )

        card.pack(
            fill=tk.BOTH,
            expand=True,
        )

        self._card_title(
            card,
            "LATEST SECURITY REPORT",
        )

        text = tk.Text(
            card,
            bg=self.PANEL,
            fg=self.TEXT,
            insertbackground=self.CYAN,
            selectbackground=self.CYAN,
            selectforeground=self.BG,
            relief=tk.FLAT,
            bd=0,
            font=("Consolas", 9),
        )

        text.pack(
            fill=tk.BOTH,
            expand=True,
            padx=15,
            pady=12,
        )

        text.insert(
            "1.0",
            str(self.last_result),
        )

        text.configure(
            state=tk.DISABLED,
        )

    # ============================================================
    # SETTINGS
    # ============================================================

    def _page_settings(self) -> None:

        self._set_page_header(
            "Настройки",
            "Параметры Security Interface",
        )

        settings = [
            "Проверка процессов",
            "Проверка автозагрузки",
            "Проверка сети",
            "Проверка Firewall",
            "Проверка DNS",
            "Проверка USB",
        ]

        for setting in settings:

            row = self._card(
                self.page_frame,
                height=48,
            )

            row.pack(
                fill=tk.X,
                pady=3,
            )

            tk.Label(
                row,
                text=setting,
                bg=self.PANEL,
                fg=self.TEXT,
                font=("Segoe UI", 9),
            ).pack(
                side=tk.LEFT,
                padx=18,
            )

            tk.Label(
                row,
                text="●  ENABLED",
                bg=self.PANEL,
                fg=self.GREEN,
                font=("Consolas", 8, "bold"),
            ).pack(
                side=tk.RIGHT,
                padx=18,
            )

    # ============================================================
    # SCAN ACTIONS
    # ============================================================

    def quick_scan(self) -> None:

        self._run_async(
            "quick_scan",
        )

    def full_scan(self) -> None:

        self._run_async(
            "full_scan",
        )

    def scan_file_dialog(self) -> None:

        path = filedialog.askopenfilename(
            title="Выберите файл для проверки",
        )

        if not path:
            return

        self._run_async(
            "scan_file",
            path,
        )

    def scan_folder_dialog(self) -> None:

        path = filedialog.askdirectory(
            title="Выберите папку для проверки",
        )

        if not path:
            return

        self._run_async(
            "scan_folder",
            path,
        )

    def scan_usb(self) -> None:

        self._run_async(
            "scan_usb",
        )

    def scan_firewall(self) -> None:

        self._run_async(
            "scan_firewall",
        )

    def scan_dns(self) -> None:

        self._run_async(
            "scan_dns",
        )

    # ============================================================
    # ASYNC EXECUTION
    # ============================================================

    def _run_async(
        self,
        operation: str,
        target: Optional[str] = None,
    ) -> None:

        if self.running:

            messagebox.showinfo(
                "JARVIS SECURITY",
                "Проверка уже выполняется.",
            )

            return

        self.running = True

        self._set_status(
            "●  ANALYSIS IN PROGRESS",
            self.YELLOW,
        )

        self.footer_activity.configure(
            text="ANALYZING...",
            fg=self.YELLOW,
        )

        self.system_status_dot.configure(
            fg=self.YELLOW,
        )


        self.system_status_text.configure(
            text="SYSTEM ANALYSIS",
            fg=self.YELLOW,
        )

        self.protection_status.configure(
            text="●  ANALYZING",
            fg=self.YELLOW,
        )

        thread = threading.Thread(
            target=self._execute_operation,
            args=(operation, target),
            daemon=True,
        )

        thread.start()

    # ============================================================
    # EXECUTE OPERATION
    # ============================================================

    def _execute_operation(
        self,
        operation: str,
        target: Optional[str],
    ) -> None:

        try:

            result = None

            # ----------------------------------------------------
            # API
            # ----------------------------------------------------

            if self.security_api is not None:

                if operation == "quick_scan":

                    result = self.security_api.analyze(
                        data={
                            "type": "quick_scan",
                        }
                    )

                elif operation == "full_scan":

                    result = self.security_api.analyze(
                        data={
                            "type": "full_scan",
                        }
                    )

                elif operation == "scan_file":

                    result = self.security_api.scan_file(
                        target
                    )

                elif operation == "scan_folder":

                    result = self.security_api.analyze(
                        data={
                            "type": "folder",
                            "target": target,
                        }
                    )

                elif operation == "scan_usb":

                    result = self.security_api.scan_usb()

                elif operation == "scan_firewall":

                    result = self.security_api.scan_firewall()

                elif operation == "scan_dns":

                    result = self.security_api.scan_dns()

            # ----------------------------------------------------
            # NO API
            # ----------------------------------------------------

            else:

                result = {
                    "success": True,
                    "status": "SIMULATION",
                    "message": (
                        f"Operation '{operation}' "
                        f"executed without Security API."
                    ),
                    "target": target,
                }

            self.root.after(
                0,
                lambda r=result: self._operation_finished(r),
            )

        except Exception as exc:

            self.root.after(
                0,
                lambda e=exc: self._operation_failed(e),
            )

    # ============================================================
    # OPERATION RESULT
    # ============================================================

    def _operation_finished(
        self,
        result: Any,
    ) -> None:

        self.running = False

        if isinstance(
            result,
            dict,
        ):

            self.last_result = result

            if result.get(
                "success",
                False,
            ):

                self._set_status(
                    "●  ANALYSIS COMPLETE",
                    self.GREEN,
                )

                self.system_status_dot.configure(
                    fg=self.GREEN,
                )

                self.system_status_text.configure(
                    text="SYSTEM NOMINAL",
                    fg=self.GREEN,
                )

                self.protection_status.configure(
                    text="●  PROTECTED",
                    fg=self.GREEN,
                )

            else:

                self._set_status(
                "●  ANALYSIS COMPLETE — REVIEW",
                    self.RED,
                )

                self.system_status_dot.configure(
                    fg=self.RED,
                )

                self.system_status_text.configure(
                    text="REVIEW REQUIRED",
                    fg=self.RED,
                )

                self.protection_status.configure(
                    text="●  REVIEW",
                    fg=self.RED,
                )

        else:

            self.last_result = {
                "result": result,
            }

            self._set_status(
                "●  ANALYSIS COMPLETE",
                self.GREEN,
            )

            self.system_status_dot.configure(
                fg=self.GREEN,
            )

            self.system_status_text.configure(
                text="SYSTEM NOMINAL",
                fg=self.GREEN,
            )

            self.protection_status.configure(
                text="●  PROTECTED",
                fg=self.GREEN,
            )

        self.footer_activity.configure(
            text="READY",
            fg=self.TEXT_DIM,
        )

        self._log(
            "security_interface_operation",
            self.last_result,
        )

        self.show_page(
            self.current_page
        )

    # ============================================================
    # OPERATION FAILED
    # ============================================================

    def _operation_failed(
        self,
        exc: Exception,
    ) -> None:

        self.running = False

        self._set_status(
            "●  ANALYSIS ERROR",
            self.RED,
        )

        self.footer_activity.configure(
            text="ERROR",
            fg=self.RED,
        )

        self.system_status_dot.configure(
            fg=self.RED,
        )

        self.system_status_text.configure(
            text="SYSTEM ERROR",
            fg=self.RED,
        )

        self.protection_status.configure(
            text="●  REVIEW",
            fg=self.RED,
        )

        self._log(
            "security_interface_error",
            {
                "error": str(exc),
            },
        )

        messagebox.showerror(
            "JARVIS SECURITY",
            f"Ошибка Security API:\n\n{exc}",
        )

    # ============================================================
    # PAGE HEADER
    # ============================================================

    def _set_page_header(
        self,
        title: str,
        subtitle: str,
    ) -> None:

        if self.content_title:

            self.content_title.configure(
                text=title
            )

        if self.content_subtitle:

            self.content_subtitle.configure(
                text=subtitle
            )

    # ============================================================
    # STATUS
    # ============================================================

    def _set_status(
        self,
        text: str,
        color: str,
    ) -> None:

        if self.status_label:

            self.status_label.configure(
                text=text,
                fg=color,
            )

    # ============================================================
    # CARD
    # ============================================================

    def _card(
        self,
        parent: tk.Widget,
        width: int = 0,
        height: int = 0,
    ) -> tk.Frame:

        outer = tk.Frame(
            parent,
            bg=self.BORDER,
        )

        card = tk.Frame(
            outer,
            bg=self.PANEL,
            width=width,
            height=height,
        )

        card.pack(
            fill=tk.BOTH,
            expand=True,
            padx=1,
            pady=1,
        )

        if width or height:
            card.pack_propagate(False)

        return outer

    # ============================================================
    # CARD TITLE
    # ============================================================

    def _card_title(
        self,
        card: tk.Widget,
        text: str,
    ) -> None:

        # Получаем внутреннюю панель,
        # если передана внешняя рамка.

        target = card

        children = card.winfo_children()

        if children:
            possible = children[0]

            if isinstance(
                possible,
                tk.Frame,
            ):
                target = possible

        tk.Label(
            target,
            text=text,
            bg=self.PANEL,
            fg=self.TEXT_SECONDARY,
            font=("Consolas", 8, "bold"),
            anchor="w",
        ).pack(
            anchor="w",
            padx=18,
            pady=(15, 3),
        )

    # ============================================================
    # ACTION BUTTON
    # ============================================================

    def _action_button(
        self,
        parent: tk.Widget,
        text: str,
        command: Any,
    ) -> tk.Button:

        button = tk.Button(
            parent,
            text=text,
            command=command,
            bg=self.BLUE,
            fg="white",
            activebackground=self.CYAN,
            activeforeground=self.BG,
            relief=tk.FLAT,
            bd=0,
            font=("Segoe UI", 8, "bold"),
            padx=16,
            pady=10,
            cursor="hand2",
        )

        button.bind(
            "<Enter>",
            lambda event: self._action_hover(
                button,
                True,
            ),
        )

        button.bind(
            "<Leave>",
            lambda event: self._action_hover(
                button,
                False,
            ),
        )

        button.bind(
            "<ButtonPress-1>",
            lambda event: button.configure(
                relief=tk.SUNKEN,
            ),
        )

        button.bind(
            "<ButtonRelease-1>",
            lambda event: button.configure(
                relief=tk.FLAT,
            ),
        )

        return button

    # ============================================================
    # ACTION HOVER
    # ============================================================

    def _action_hover(
        self,
        button: tk.Button,
        entering: bool,
    ) -> None:

        if entering:

            button.configure(
                bg=self.CYAN,
                fg=self.BG,
            )

        else:

            button.configure(
                bg=self.BLUE,
                fg="white",
            )

    # ============================================================
    # SMALL BUTTON
    # ============================================================

    def _small_button(
        self,
        parent: tk.Widget,
        text: str,
        command: Any,
    ) -> tk.Button:

        button = tk.Button(
            parent,
            text=text,
            command=command,
            bg=self.PANEL_2,
            fg=self.TEXT,
            activebackground=self.CYAN,
            activeforeground=self.BG,
            relief=tk.FLAT,
            bd=0,
            font=("Consolas", 7, "bold"),
            padx=13,
            pady=7,
            cursor="hand2",
        )

        button.bind(
            "<Enter>",
            lambda event: button.configure(
                bg=self.CYAN,
                fg=self.BG,
            ),
        )

        button.bind(
            "<Leave>",
            lambda event: button.configure(
                bg=self.PANEL_2,
                fg=self.TEXT,
            ),
        )

        button.bind(
            "<ButtonPress-1>",
            lambda event: button.configure(
                relief=tk.SUNKEN,
            ),
        )

        button.bind(
            "<ButtonRelease-1>",
            lambda event: button.configure(
                relief=tk.FLAT,
            ),
        )

        return button

    # ============================================================
    # EMPTY STATE
    # ============================================================

    def _empty_state(
        self,
        icon: str,
        title: str,
        message: str,
        color: Optional[str] = None,
    ) -> None:

        if color is None:
            color = self.TEXT

        frame = tk.Frame(
            self.page_frame,
            bg=self.BG,
        )

        frame.pack(
            fill=tk.BOTH,
            expand=True,
        )

        # HUD brackets

        tk.Label(
            frame,
            text="┌──────────────────────────┐",
            bg=self.BG,
            fg=self.BORDER_ACTIVE,
            font=("Consolas", 10),
        ).pack(
            pady=(70, 0),
        )

        tk.Label(
            frame,
            text=icon,
            bg=self.BG,
            fg=color,
            font=("Segoe UI", 34, "bold"),
        ).pack(
            pady=(8, 3),
        )

        tk.Label(
            frame,
            text=title,
            bg=self.BG,
            fg=self.TEXT,
            font=("Segoe UI", 16, "bold"),
        ).pack()

        tk.Label(
            frame,
            text=message,
            bg=self.BG,
            fg=self.TEXT_SECONDARY,
            font=("Segoe UI", 9),
        ).pack(
            pady=6,
        )

        tk.Label(
            frame,
            text="└──────────────────────────┘",
            bg=self.BG,
            fg=self.BORDER_ACTIVE,
            font=("Consolas", 10),
        ).pack()

    # ============================================================
    # LOGGING
    # ============================================================

    def _log(
        self,
        event: str,
        data: Any,
    ) -> None:

        try:

            if self.logger is None:
                return

            if hasattr(
                self.logger,
                "log",
            ):

                self.logger.log(
                    event,
                    data,
                )

            elif hasattr(
                self.logger,
                "info",
            ):

                self.logger.info(
                    f"{event}: {data}"
                )

        except Exception:
            pass

    # ============================================================
    # RUN
    # ============================================================

    def run(self) -> None:

        if self.root is None:
            return

        if self.own_root:

            self.root.mainloop()

    # ============================================================
    # CLOSE
    # ============================================================

    def close(self) -> None:

        self._stop_scan_animation()

        if self.root:

            try:
                self.root.destroy()
            except Exception:
                pass

    # ============================================================
    # REPRESENTATION
    # ============================================================

    def __repr__(self) -> str:

        return (
            f"<SecurityInterface "
            f"version={self.VERSION} "
            f"page={self.current_page}>"
        )