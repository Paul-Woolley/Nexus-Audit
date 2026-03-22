"""
engine/theme.py
================
Centralized color theme management for Nexus Audit Tool.

Provides consistent blue-team/audit-style ANSI color codes for terminal output.
No external dependencies - uses only standard Python.
"""


class Theme:
    """
    Centralized color theme for Nexus Audit Tool.
    
    Uses ANSI escape codes for professional blue-team/audit styling.
    Color palette:
        - Primary accent: #4384b5 (blue)
        - Dark base tone: #22394a (dark blue-gray)
        - Success/Info: Green tones
        - Warning: Yellow/Orange tones
        - Error/Critical: Red tones
    """
    
    # ANSI color codes
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[90m"
    
    # Primary colors (blue-team theme)
    PRIMARY = "\033[38;5;67m"      # #4384b5 - main accent
    PRIMARY_BOLD = "\033[1;38;5;67m"
    
    DARK_BASE = "\033[38;5;23m"     # #22394a - dark base tone
    DARK_BASE_BOLD = "\033[1;38;5;23m"
    
    # Status colors
    SUCCESS = "\033[38;5;34m"      # Green
    SUCCESS_BOLD = "\033[1;38;5;34m"
    
    WARNING = "\033[38;5;172m"      # Orange/Yellow
    WARNING_BOLD = "\033[1;38;5;172m"
    
    ERROR = "\033[38;5;196m"        # Red
    ERROR_BOLD = "\033[1;38;5;196m"
    
    # Risk level colors (refined for clarity and hierarchy)
    CRITICAL = "\033[1;38;5;196m"   # Strong red (critical issues)
    HIGH     = "\033[1;38;5;202m"   # Deep orange (serious but not critical)
    MEDIUM   = "\033[1;38;5;220m"   # Clear yellow (true caution)
    LOW      = "\033[1;38;5;70m"    # Soft green (low risk)
    INFO     = "\033[1;38;5;245m"   # Neutral gray (informational)
    
    # Section and header colors
    HEADER = "\033[1;38;5;67m"      # Blue
    SECTION = "\033[38;5;67m"       # Blue
    SUBSECTION = "\033[38;5;109m"   # Lighter blue
    
    # Data colors
    DATA_KEY = "\033[38;5;109m"     # Light blue
    DATA_VALUE = "\033[38;5;255m"   # White
    
    # UI elements
    MENU_NUMBER = "\033[1;38;5;67m"
    MENU_ITEM = "\033[38;5;255m"
    PROMPT = "\033[1;38;5;67m"
    
    @staticmethod
    def primary(text: str) -> str:
        """Format text in primary accent color."""
        return f"{Theme.PRIMARY}{text}{Theme.RESET}"
    
    @staticmethod
    def success(text: str) -> str:
        """Format text in success color."""
        return f"{Theme.SUCCESS}{text}{Theme.RESET}"
    
    @staticmethod
    def warning(text: str) -> str:
        """Format text in warning color."""
        return f"{Theme.WARNING}{text}{Theme.RESET}"
    
    @staticmethod
    def error(text: str) -> str:
        """Format text in error color."""
        return f"{Theme.ERROR}{text}{Theme.RESET}"
    
    @staticmethod
    def bold(text: str) -> str:
        """Format text in bold."""
        return f"{Theme.BOLD}{text}{Theme.RESET}"
    
    @staticmethod
    def dim(text: str) -> str:
        """Format text in dim/faded color."""
        return f"{Theme.DIM}{text}{Theme.RESET}"
    
    @staticmethod
    def header(text: str) -> str:
        """Format text as a section header."""
        return f"{Theme.HEADER}{text}{Theme.RESET}"
    
    @staticmethod
    def risk_color(risk: str) -> str:
        """Get color code for a risk level."""
        colors = {
            "Critical": Theme.CRITICAL,
            "High": Theme.HIGH,
            "Medium": Theme.MEDIUM,
            "Low": Theme.LOW,
            "Info": Theme.INFO,
        }
        color = colors.get(risk, Theme.RESET)
        return f"{color}{risk}{Theme.RESET}"


class Banner:
    """Professional banner display for Nexus Audit Tool."""
    
    WIDTH = 70
    
    @staticmethod
    def display() -> None:
        """Display the tool banner with dynamic width."""

        raw_banner = '''

        
    ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗      █████╗ ██╗   ██╗██████╗ ██╗████████╗
    ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝     ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
    ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║████████████████████║██║   ██║██║  ██║██║   ██║
    ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║     ██╔══██║██║   ██║██║  ██║██║   ██║
    ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║     ██║  ██║╚██████╔╝██████╔╝██║   ██║
    ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝
    '''

        lines = raw_banner.strip("\n").split("\n")
        max_width = max(len(line) for line in lines)

        border = Theme.dim("=" * (max_width + 8))

        print("\n" + border)

        for line in lines:
            print(f"    {Theme.primary(Theme.BOLD + line)}{Theme.RESET}")

        subtitle = "Security Audit & Log Analysis Framework"
        padding = (max_width - len(subtitle)) // 2
        print("\n" + " " * (padding + 2) + Theme.dim(subtitle))

        print(border + "\n")
        
    @staticmethod
    def display_small() -> None:
        """Display a compact banner."""
        print(f"\n  {Theme.primary(Theme.BOLD + 'NEXUS-AUDIT')}{Theme.RESET}")
        print(f"  {Theme.dim('Security Audit & Log Analysis Framework')}")
        print(f"  {Theme.dim('-' * 55)}\n")


class Menu:
    """Interactive menu system for Nexus Audit Tool."""
    
    @staticmethod
    def clear_screen() -> None:
        """Clear the terminal screen."""
        print("\033[2J\033[H", end="")
    
    @staticmethod
    def show_main_menu() -> None:
        """Display the main interactive menu."""
        print(f"\n  {Theme.header('MAIN MENU')}")
        print(f"  {Theme.dim('-' * 50)}")
        print()
        print(f"  {Theme.MENU_NUMBER}[1]{Theme.RESET} Run Scan")
        print(f"  {Theme.MENU_NUMBER}[2]{Theme.RESET} Generate Report from Findings")
        print(f"  {Theme.MENU_NUMBER}[3]{Theme.RESET} List Detection Rules")
        print(f"  {Theme.MENU_NUMBER}[4]{Theme.RESET} Exit")
        print()
    
    @staticmethod
    def get_choice(prompt: str = "Select option") -> str:
        """Get user choice from menu."""
        try:
            choice = input(f"  {Theme.PROMPT}{prompt} [1-4]: {Theme.RESET}").strip()
            return choice
        except (EOFError, KeyboardInterrupt):
            return "4"  # Exit on interrupt
    
    @staticmethod
    def get_input(prompt: str, default: str = "") -> str:
        """Get user input with optional default value."""
        try:
            if default:
                prompt_text = f"  {Theme.PROMPT}{prompt} [{default}]: {Theme.RESET}"
                value = input(prompt_text).strip()
                return value if value else default
            else:
                prompt_text = f"  {Theme.PROMPT}{prompt}: {Theme.RESET}"
                return input(prompt_text).strip()
        except (EOFError, KeyboardInterrupt):
            raise
    
    @staticmethod
    def get_yes_no(prompt: str, default: str = "n") -> bool:
        """Get yes/no confirmation from user."""
        while True:
            try:
                choice = input(
                    f"  {Theme.PROMPT}{prompt} [Y/n]: {Theme.RESET}"
                ).strip().lower()
                if not choice:
                    choice = default
                if choice in ["y", "yes"]:
                    return True
                elif choice in ["n", "no"]:
                    return False
                else:
                    print(f"  {Theme.warning('Please enter Y or N')}")
            except (EOFError, KeyboardInterrupt):
                return False
    
    @staticmethod
    def press_enter_to_continue() -> None:
        """Wait for user to press Enter."""
        try:
            input(f"  {Theme.dim('Press Enter to continue...')}")
        except (EOFError, KeyboardInterrupt):
            pass
    
    @staticmethod
    def section(title: str) -> None:
        """Display a section header."""
        print(f"\n  {Theme.header('>>')} {Theme.bold(title)}")
        print(f"  {Theme.dim('-' * 50)}")
    
    @staticmethod
    def success(message: str) -> None:
        """Display a success message."""
        print(f"  {Theme.success('>>')} {message}")
    
    @staticmethod
    def warning(message: str) -> None:
        """Display a warning message."""
        print(f"  {Theme.warning('>>')} {message}")
    
    @staticmethod
    def error(message: str) -> None:
        """Display an error message."""
        print(f"  {Theme.error('>> ERROR')} {message}", file=__import__("sys").stderr)
    
    @staticmethod
    def info(message: str) -> None:
        """Display an informational message."""
        print(f"  {Theme.dim('>>')} {message}")
    
    @staticmethod
    def result(label: str, value: str) -> None:
        """Display a key-value result."""
        print(f"  {Theme.DATA_KEY}{label}:{Theme.RESET} {value}")