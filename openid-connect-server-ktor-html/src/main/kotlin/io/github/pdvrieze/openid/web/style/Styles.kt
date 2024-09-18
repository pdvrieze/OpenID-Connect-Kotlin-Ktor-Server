package io.github.pdvrieze.openid.web.style

import kotlinx.css.Color
import kotlinx.css.CssBuilder
import kotlinx.css.FontWeight
import kotlinx.css.LinearDimension
import kotlinx.css.Padding

interface Styles {

    val vars: Vars

    val mixins: Mixins

    interface Vars {
        // Grays
        // -------------------------
                val black: Color
        val grayDarker: Color
        val grayDark: Color
        val gray: Color
        val grayLight: Color
        val grayLighter: Color
        val white: Color

        // Accent colors
        // -------------------------
                val blue: Color
        val blueDark: Color
        val green: Color
        val red: Color
        val yellow: Color
        val orange: Color
        val pink: Color
        val purple: Color

        // Scaffolding
        // -------------------------
                val bodyBackground: Color
        val textColor: Color

        // Links
        // -------------------------
                val linkColor: Color
        val linkColorHover: Color

        // Typography
        // -------------------------
                val sansFontFamily: String
        val serifFontFamily: String
        val monoFontFamily: String
        val baseFontSize: LinearDimension
        val baseFontFamily: String
        val baseLineHeight: LinearDimension
        val altFontFamily: String
        val headingsFontFamily: String

        // empty to use BS default, VARbaseFontFamily
        val headingsFontWeight: FontWeight

        // instead of browser default, bold
        val headingsColor: Color
        val fontSizeLarge: LinearDimension

        // ~18px
        val fontSizeSmall: LinearDimension

        // ~12px
        val fontSizeMini: LinearDimension
        val paddingLarge: Padding

        // 44px
        val paddingSmall: Padding

        // 26px
        val paddingMini: Padding
        val baseBorderRadius: LinearDimension
        val borderRadiusLarge: LinearDimension
        val borderRadiusSmall: LinearDimension

        // Tables
        // -------------------------
                val tableBackground: Color

        // overall background-color
        val tableBackgroundAccent: Color

        // for striping
        val tableBackgroundHover: Color

        // for hover
        val tableBorder: Color

        // Buttons
        // -------------------------
                val btnBackground: Color
        val btnBackgroundHighlight: Color
        val btnBorder: Color
        val btnPrimaryBackground: Color

        // Spin 20% from btnPrimaryBackground
        val btnPrimaryBackgroundHighlight: Color
        val btnInfoBackground: Color
        val btnInfoBackgroundHighlight: Color
        val btnSuccessBackground: Color
        val btnSuccessBackgroundHighlight: Color
        val btnWarningBackground: Color
        val btnWarningBackgroundHighlight: Color
        val btnDangerBackground: Color
        val btnDangerBackgroundHighlight: Color
        val btnInverseBackground: Color
        val btnInverseBackgroundHighlight: Color

        // Forms
        // -------------------------
                val inputBackground: Color
        val inputBorder: Color
        val inputBorderRadius: LinearDimension
        val inputDisabledBackground: Color
        val formActionsBackground: Color
        val inputHeight: LinearDimension

        // Dropdowns
        // -------------------------
                val dropdownBackground: Color
        val dropdownBorder: Color
        val dropdownDividerTop: Color
        val dropdownDividerBottom: Color
        val dropdownLinkColor: Color
        val dropdownLinkColorHover: Color
        val dropdownLinkColorActive: Color
        val dropdownLinkBackgroundActive: Color
        val dropdownLinkBackgroundHover: Color

        // Z-index master list
        // -------------------------
        // Used for a bird's eye view of components dependent on the z-axis
        // Try to avoid customizing these :)
                val zindexDropdown: Int
        val zindexPopover: Int
        val zindexTooltip: Int
        val zindexFixedNavbar: Int
        val zindexModalBackdrop: Int
        val zindexModal: Int

        // Sprite icons path
        // -------------------------
                val iconSpritePath: String
        val iconWhiteSpritePath: String

        // Input placeholder text color
        // -------------------------
                val placeholderText: Color

        // Hr border color
        // -------------------------
                val hrBorder: Color

        // Horizontal forms & lists
        // -------------------------
                val horizontalComponentOffset: LinearDimension

        // Wells
        // -------------------------
                val wellBackground: Color

        // Navbar
        // -------------------------
                val navbarCollapseWidth: LinearDimension
        val navbarCollapseDesktopWidth: LinearDimension
        val navbarHeight: LinearDimension
        val navbarBackgroundHighlight: Color
        val navbarBackground: Color
        val navbarBorder: Color
        val navbarText: Color
        val navbarLinkColor: Color
        val navbarLinkColorHover: Color
        val navbarLinkColorActive: Color
        val navbarLinkBackgroundHover: Color
        val navbarLinkBackgroundActive: Color
        val navbarBrandcolor: Color

        // Inverted navbar
                val navbarInverseBackground: Color
        val navbarInverseBackgroundHighlight: Color
        val navbarInverseBorder: Color
        val navbarInverseText: Color
        val navbarInverseLinkcolor: Color
        val navbarInverseLinkColorHover: Color
        val navbarInverseLinkColorActive: Color
        val navbarInverseLinkBackgroundHover: Color
        val navbarInverseLinkBackgroundActive: Color
        val navbarInverseSearchBackground: Color
        val navbarInverseSearchBackgroundFocus: Color
        val navbarInverseSearchBorder: Color
        val navbarInverseSearchPlaceholderColor: Color
        val navbarInverseBrandcolor: Color

        // Pagination
        // -------------------------
                val paginationBackground: Color
        val paginationBorder: Color
        val paginationActiveBackground: Color

        // Hero unit
        // -------------------------
                val heroUnitBackground: Color
        val heroUnitHeadingColor: Color
        val heroUnitLeadColor: Color

        // Form states and alerts
        // -------------------------
                val warningText: Color
        val warningBackground: Color

        // darken(spin(VARwarningBackground, -10), 3%);
        val warningBorder: Color
        val errorText: Color
        val errorBackground: Color

        // darken(spin(VARerrorBackground, -10), 3%);
        val errorBorder: Color
        val successText: Color
        val successBackground: Color

        // darken(spin(VARsuccessBackground, -10), 5%);
        val successBorder: Color
        val infoText: Color
        val infoBackground: Color

        // darken(spin(VARinfoBackground, -10), 7%);
        val infoBorder: Color

        // Tooltips and popovers
        // -------------------------
                val tooltipColor: Color
        val tooltipBackground: Color
        val tooltipArrowWidth: LinearDimension
        val tooltipArrowcolor: Color
        val popoverBackground: Color
        val popoverArrowWidth: LinearDimension
        val popoverArrowColor: Color
        val popoverTitleBackground: Color

        // Special enhancement for popovers
                val popoverArrowOuterWidth: LinearDimension
        val popoverArrowOuterColor: Color

        // Default 940px grid
        // -------------------------
                val gridColumns: Int
        val gridColumnWidth: LinearDimension
        val gridGutterWidth: LinearDimension
        val gridRowWidth: LinearDimension

        // 1200px min
                val gridColumnWidth1200: LinearDimension
        val gridGutterWidth1200: LinearDimension
        val gridRowWidth1200: LinearDimension

        // 768px-979px
                val gridColumnWidth768: LinearDimension
        val gridGutterWidth768: LinearDimension
        val gridRowWidth768: LinearDimension

        // Fluid grid
        // -------------------------
                val fluidGridColumnWidth: LinearDimension
        val fluidGridGutterWidth: LinearDimension

        // 1200px min
                val fluidGridColumnWidth1200: LinearDimension
        val fluidGridGutterWidth1200: LinearDimension

        // 768px-979px
                val fluidGridColumnWidth768: LinearDimension
        val fluidGridGutterWidth768: LinearDimension

    }

    fun CssBuilder.accordion()

    fun CssBuilder.alerts()

    fun CssBuilder.bootstrap() {
        // Core variables and mixins
        variables()

        // CSS Reset
        reset()

        // Grid system and page structure
        scaffolding()
        grid()
        layouts()

        // Base CSS
        type()
        code()
        forms()
        tables()

        // Components: common
        sprites()
        dropdowns()
        wells()
        componentAnimations()
        close()

        // Components: Buttons & Alerts
        buttons()
        buttonGroups()
        alerts()

        // Components: Nav
        navs()
        navbar()
        breadcrumbs()
        pagination()
        pager()

        // Components: Popovers
        modals()
        tooltip()
        popovers()

        // Components: Misc
        thumbnails()
        media()
        labelsBadges()
        progressBars()
        accordion()
        carousel()
        heroUnit()

        // Utility classes
        utilities() // Has to be last to override when necessary
    }

    fun CssBuilder.bootstrapResponsive(){
        variables()
        responsiveUtilities()
        responsive1200pxMin()
        responsive768px979px()
        responsive767pxMax()
        responsiveNavbar()
    }

    fun CssBuilder.breadcrumbs()
    fun CssBuilder.buttonGroups()
    fun CssBuilder.buttons()
    fun CssBuilder.carousel()
    fun CssBuilder.close()
    fun CssBuilder.code()
    fun CssBuilder.componentAnimations()
    fun CssBuilder.dropdowns()
    fun CssBuilder.forms()
    fun CssBuilder.grid()
    fun CssBuilder.heroUnit()
    fun CssBuilder.labelsBadges()
    fun CssBuilder.layouts()
    fun CssBuilder.media()
    fun CssBuilder.modals()
    fun CssBuilder.navbar()
    fun CssBuilder.navs()
    fun CssBuilder.pager()
    fun CssBuilder.pagination()
    fun CssBuilder.popovers()
    fun CssBuilder.progressBars()
    fun CssBuilder.reset()
    fun CssBuilder.responsive1200pxMin()
    fun CssBuilder.responsive767pxMax()
    fun CssBuilder.responsive768px979px()
    fun CssBuilder.responsiveNavbar()
    fun CssBuilder.responsiveUtilities()
    fun CssBuilder.scaffolding()
    fun CssBuilder.sprites()
    fun CssBuilder.tables()
    fun CssBuilder.thumbnails()
    fun CssBuilder.tooltip()
    fun CssBuilder.type()
    fun CssBuilder.utilities()
    fun CssBuilder.variables()
    fun CssBuilder.wells()
}
