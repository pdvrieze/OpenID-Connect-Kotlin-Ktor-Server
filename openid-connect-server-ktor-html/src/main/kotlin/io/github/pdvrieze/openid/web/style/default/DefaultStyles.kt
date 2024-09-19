package io.github.pdvrieze.openid.web.style.default

import io.github.pdvrieze.openid.web.style.Mixins
import io.github.pdvrieze.openid.web.style.Styles
import io.github.pdvrieze.openid.web.style.borderWidth
import io.github.pdvrieze.openid.web.style.default.DefaultMixins.gradientStriped
import io.github.pdvrieze.openid.web.style.ruleOf
import io.github.pdvrieze.openid.web.style.zoom
import kotlinx.css.*
import kotlinx.css.Float
import kotlinx.css.properties.Animation
import kotlinx.css.properties.BoxShadow
import kotlinx.css.properties.BoxShadowInset
import kotlinx.css.properties.BoxShadows
import kotlinx.css.properties.LineHeight
import kotlinx.css.properties.TextDecoration
import kotlinx.css.properties.TextDecorationLine
import kotlinx.css.properties.Time
import kotlinx.css.properties.Timing
import kotlinx.css.properties.lh
import kotlinx.css.properties.s


object DefaultStyles : Styles {

    override val vars: Styles.Vars
        get() = DefaultVars

    override val mixins: Mixins
        get() = DefaultMixins

    fun percentage(numerator: LinearDimension, denumerator: LinearDimension): LinearDimension {
        require(numerator is NumericLinearDimension)
        require(denumerator is NumericLinearDimension)
        require(numerator.unit == denumerator.unit) { "Unit mismatch in percentage" }
        return NumericLinearDimension((100*numerator.number.toFloat())/denumerator.number.toFloat(), "%")
    }

    object DefaultVars : Styles.Vars {
        // Grays
        override val black = Color("000")
        override val grayDarker = Color("222")
        override val grayDark = Color("333")
        override val gray = Color("555")
        override val grayLight = Color("999")
        override val grayLighter = Color("eee")
        override val white = Color("fff")


        // Accent colors
        override val blue = Color("049cdb")
        override val blueDark = Color("0064cd")
        override val green = Color("46a546")
        override val red = Color("9d261d")
        override val yellow = Color("ffc40d")
        override val orange = Color("f89406")
        override val pink = Color("c3325f")
        override val purple = Color("7a43b6")


        // Scaffolding
        override val bodyBackground get() = white
        override val textColor = grayDark


        // Links
        override val linkColor = Color("08c")
        override val linkColorHover get() = linkColor.darken(15)


        // Typography
        override val sansFontFamily = "\"Helvetica Neue\", Helvetica, Arial, sans-serif"
        override val serifFontFamily = "Georgia, \"Times New Roman\", Times, serif"
        override val monoFontFamily = "Monaco, Menlo, Consolas, \"Courier New\", monospace"

        override val baseFontSize = 14.px
        override val baseFontFamily get() = sansFontFamily
        override val baseLineHeight = 20.px
        override val altFontFamily get() = serifFontFamily

        override val headingsFontFamily = "inherit"

        // empty to use BS default, vars.baseFontFamily
        override val headingsFontWeight = FontWeight.bold

        // instead of browser default, bold
        override val headingsColor = Color.inherit
        // empty to use BS default, vars.textColor


        // Component sizing
        // Based on 14px font-size and 20px line-height

        override val fontSizeLarge get() = baseFontSize * 1.25

        // ~18px
        override val fontSizeSmall get() = baseFontSize * 0.85

        // ~12px
        override val fontSizeMini get() = baseFontSize * 0.75
        // ~11px

        override val paddingLarge = Padding(11.px, 19.px)

        // 44px
        override val paddingSmall = Padding(2.px, 10.px)

        // 26px
        override val paddingMini = Padding(0.px, 6.px)
        // 22px

        override val baseBorderRadius = 4.px
        override val borderRadiusLarge = 6.px
        override val borderRadiusSmall = 3.px


        // Tables
        override val tableBackground = Color.transparent

        // overall background-color
        override val tableBackgroundAccent = Color("f9f9f9")

        // for striping
        override val tableBackgroundHover = Color("f5f5f5")

        // for hover
        override val tableBorder = Color("ddd")
        // table and cell border

        // Buttons
        override val btnBackground get() = white
        override val btnBackgroundHighlight get() = white.darken(10)
        override val btnBorder = Color("ccc")

        override val btnPrimaryBackground get() = linkColor

        // Spin 20% from btnPrimaryBackground
        override val btnPrimaryBackgroundHighlight: Color = hsl(251, 255, 204)

        override val btnInfoBackground = Color("5bc0de")
        override val btnInfoBackgroundHighlight = Color("2f96b4")

        override val btnSuccessBackground = Color("62c462")
        override val btnSuccessBackgroundHighlight = Color("51a351")

        override val btnWarningBackground = orange.lighten(15)
        override val btnWarningBackgroundHighlight get() = orange

        override val btnDangerBackground = Color("ee5f5b")
        override val btnDangerBackgroundHighlight = Color("bd362f")

        override val btnInverseBackground = Color("444")
        override val btnInverseBackgroundHighlight get() = grayDarker


        // Forms
        override val inputBackground get() = white
        override val inputBorder = Color("ccc")
        override val inputBorderRadius get() = baseBorderRadius
        override val inputDisabledBackground get() = grayLighter
        override val formActionsBackground = Color("f5f5f5")
        override val inputHeight get() = LinearDimension(baseLineHeight.value) + 10.px
        // base line-height + 8px vertical padding + 2px top/bottom border


        // Dropdowns
        override val dropdownBackground get() = white
        override val dropdownBorder = rgb(0, 0, 0, .2)
        override val dropdownDividerTop = Color("e5e5e5")
        override val dropdownDividerBottom get() = white

        override val dropdownLinkColor get() = grayDark
        override val dropdownLinkColorHover get() = white
        override val dropdownLinkColorActive get() = white

        override val dropdownLinkBackgroundActive get() = linkColor
        override val dropdownLinkBackgroundHover get() = dropdownLinkBackgroundActive


// COMPONENT VARIABLES


        // Z-index master list
// Used for a bird's eye view of components dependent on the z-axis
// Try to avoid customizing these :)
        override val zindexDropdown = 1000
        override val zindexPopover = 1010
        override val zindexTooltip = 1030
        override val zindexFixedNavbar = 1030
        override val zindexModalBackdrop = 1040
        override val zindexModal = 1050


        // Sprite icons path
        override val iconSpritePath = "../img/glyphicons-halflings.png"
        override val iconWhiteSpritePath = "../img/glyphicons-halflings-white.png"


        // Input placeholder text color
        override val placeholderText get() = grayLight


        // Hr border color
        override val hrBorder get() = grayLighter


        // Horizontal forms & lists
        override val horizontalComponentOffset = 180.px


        // Wells
        override val wellBackground = Color("f5f5f5")


        // Navbar
        override val navbarCollapseWidth = 979.px
        override val navbarCollapseDesktopWidth = navbarCollapseWidth + 1.px

        override val navbarHeight = 40.px
        override val navbarBackgroundHighlight = Color("ffffff")
        override val navbarBackground = navbarBackgroundHighlight.darken(5)
        override val navbarBorder = navbarBackground.darken(12)

        override val navbarText = Color("777")
        override val navbarLinkColor = Color("777")
        override val navbarLinkColorHover get() = grayDark
        override val navbarLinkColorActive get() = gray
        override val navbarLinkBackgroundHover = Color.transparent
        override val navbarLinkBackgroundActive = navbarBackground.darken(5)

        override val navbarBrandColor get() = navbarLinkColor

        // Inverted navbar
        override val navbarInverseBackground = Color("111111")
        override val navbarInverseBackgroundHighlight = Color("222222")
        override val navbarInverseBorder = Color("252525")

        override val navbarInverseText get() = grayLight
        override val navbarInverseLinkColor get() = grayLight
        override val navbarInverseLinkColorHover get() = white
        override val navbarInverseLinkColorActive get() = navbarInverseLinkColorHover
        override val navbarInverseLinkBackgroundHover = Color.transparent
        override val navbarInverseLinkBackgroundActive get() = navbarInverseBackground

        override val navbarInverseSearchBackground = navbarInverseBackground.lighten(25)
        override val navbarInverseSearchBackgroundFocus get() = white
        override val navbarInverseSearchBorder get() = navbarInverseBackground
        override val navbarInverseSearchPlaceholderColor = Color("ccc")

        override val navbarInverseBrandColor get() = navbarInverseLinkColor


        // Pagination
        override val paginationBackground = Color("fff")
        override val paginationBorder = Color("ddd")
        override val paginationActiveBackground = Color("f5f5f5")


        // Hero unit
        override val heroUnitBackground get() = grayLighter
        override val heroUnitHeadingColor = Color.inherit
        override val heroUnitLeadColor = Color.inherit


        // Form states and alerts
        override val warningText = Color("c09853")
        override val warningBackground = Color("fcf8e3")

        // darken(spin(vars.warningBackground, -10), 3%)
        override val warningBorder = hsl(24, 25, 252).darken(3)

        override val errorText = Color("b94a48")
        override val errorBackground = Color("f2dede")

        // darken(spin(vars.errorBackground, -10), 3%)
        override val errorBorder = hsl(230, 21, 242).darken(3)

        override val successText = Color("468847")
        override val successBackground = Color("dff0d8")

        // darken(spin(vars.successBackground, -10), 5%)
        override val successBorder = hsl(76, 25, 240).darken(5)

        override val infoText = Color("3a87ad")
        override val infoBackground = Color("d9edf7")

        // darken(spin(vars.infoBackground, -10), 7%)
        override val infoBorder = hsl(174, 31, 247).darken(7)


        // Tooltips and popovers
        override val tooltipColor = Color("fff")
        override val tooltipBackground = Color("000")
        override val tooltipArrowWidth = 5.px
        override val tooltipArrowColor get() = tooltipBackground

        override val popoverBackground = Color("fff")
        override val popoverArrowWidth = 10.px
        override val popoverArrowColor = Color("fff")
        override val popoverTitleBackground = popoverBackground.darken(3)

        // Special enhancement for popovers
        override val popoverArrowOuterWidth = popoverArrowWidth + 1.px
        override val popoverArrowOuterColor = rgb(0, 0, 0, .25)


// GRID


        // Default 940px grid
        override val gridColumns = 12
        override val gridColumnWidth = 60.px
        override val gridGutterWidth = 20.px
        override val gridRowWidth = (gridColumnWidth * gridColumns) + (gridGutterWidth * (gridColumns-1))

        // 1200px min
        override val gridColumnWidth1200 = 70.px
        override val gridGutterWidth1200 = 30.px
        override val gridRowWidth1200 = (gridColumnWidth1200 * gridColumns) + (gridGutterWidth1200 * (gridColumns-1))

        // 768px-979px
        override val gridColumnWidth768 = 42.px
        override val gridGutterWidth768 = 20.px
        override val gridRowWidth768 = (gridColumnWidth768 * gridColumns) + (gridGutterWidth768 * (gridColumns-1))


        // Fluid grid
        override val fluidGridColumnWidth = percentage(gridColumnWidth, gridRowWidth)
        override val fluidGridGutterWidth = percentage(gridGutterWidth, gridRowWidth)

        // 1200px min
        override val fluidGridColumnWidth1200 = percentage(gridColumnWidth1200, gridRowWidth1200)
        override val fluidGridGutterWidth1200 = percentage(gridGutterWidth1200, gridRowWidth1200)

        // 768px-979px
        override val fluidGridColumnWidth768 = percentage(gridColumnWidth768, gridRowWidth768)
        override val fluidGridGutterWidth768 = percentage(gridGutterWidth768, gridRowWidth768)
    }

    override fun CssBuilder.accordion() {
        // Parent container
        rule(".accordion") {
            marginBottom = vars.baseLineHeight
        }

        // Group == heading + body
        rule(".accordion-group") {
            marginBottom = 2.px
            border = Border(1.px, BorderStyle.solid, Color("#e5e5e5"))
            borderRadius = vars.baseBorderRadius
        }

        rule(".accordion-heading") {
            borderBottomWidth = 0.px
        }

        rule(".accordion-heading .accordion-toggle") {
            display = Display.block
            padding = Padding(8.px, 15.px)
        }

        // General toggle styles
        rule(".accordion-toggle") {
            cursor = Cursor.pointer
        }

        // Inner needs the styles because you can't animate properly with any styles on the element
        rule(".accordion-inner") {
            padding = Padding(9.px, 15.px)
            borderTop = Border(1.px, BorderStyle.solid, Color("#e5e5e5"))
        }
    }

    override fun CssBuilder.alerts() {
        rule(".alert") {
            padding = Padding(8.px, 35.px, 8.px, 14.px)
            marginBottom = vars.baseLineHeight
            declarations["text-shadow"] = "0px 1px 0px rgba(255, 255, 255, .5)"
            backgroundColor = vars.warningBackground
            border = Border(1.px, BorderStyle.solid, vars.warningBorder)

            with(mixins) { borderRadius(vars.baseBorderRadius) }
        }

        rule(".alert, .alert h4") {
            // Specified for the h4 to prevent conflicts of changing vars.headingsColor
            color = vars.warningText
        }

        rule(".alert h4") {
            margin = Margin(0.px)
        }

        // Adjust close link position
        rule(".alert .close") {
            position = Position.relative
            top = -2.px
            right = -21.px
            lineHeight = vars.baseLineHeight.lh
        }

        // Alternate styles
        rule(".alert-success") {
            backgroundColor = vars.successBackground
            borderColor = vars.successBorder
            color = vars.successText
        }

        rule(".alert-success h4") {
            color = vars.successText
        }

        rule(".alert-danger, .alert-error") {
            backgroundColor = vars.errorBackground
            borderColor =  vars.errorBorder
            color = vars.errorText
        }

        rule(".alert-danger h4, .alert-error h4") {
            color = vars.errorText
        }

        rule(".alert-info") {
            backgroundColor = vars.infoBackground
            borderColor = vars.infoBorder
            color = vars.infoText
        }

        rule(".alert-info h4") {
            color = vars.infoText
        }

        // Block alerts
        rule(".alert-block") {
            paddingTop = 14.px
            paddingBottom = 14.px
        }

        rule(".alert-block > p, .alert-block > ul") {
            marginBottom = 0.px
        }

        rule(".alert-block p + p") {
            marginTop = 5.px
        }

    }

    override fun CssBuilder.breadcrumbs(){
        rule(".breadcrumb") {
            padding = Padding(8.px, 15.px)
            margin = Margin(0.px, 0.px, vars.baseLineHeight)
            listStyleType = ListStyleType.none

            backgroundColor = Color("#f5f5f5")
            with(mixins) { borderRadius(vars.baseBorderRadius) }
            child("li") {
                display = Display.inlineBlock
                with(mixins) { ie7InlineBlock() }
                declarations["text-shadow"] = "0px 1px 0px ${vars.white}"

                child(".divider") {
                    padding = Padding(0.px, 5.px)
                    color = Color("#ccc")
                }
            }
            child(".active") {
                color = vars.grayLight
            }
        }
    }


    override fun CssBuilder.buttonGroups() {
        // Make the div behave like a button
        rule(".btn-group") {
            position = Position.relative
            display = Display.inlineBlock
            with(mixins) { ie7InlineBlock() }
            fontSize = 0.px
            // remove as part 1 of font-size inline-block hack
            verticalAlign = VerticalAlign.middle
            // match .btn alignment given font-size hack above
            whiteSpace = WhiteSpace.nowrap
            // prevent buttons from wrapping when in tight spaces (e.g., the table on the tests page)
            with(mixins) { ie7RestoreLeftWhitespace() }
        }

        // Space out series of button groups
        rule(".btn-group + .btn-group") {
            marginLeft = 5.px
        }

        // Optional: Group multiple button groups together for a toolbar
        rule(".btn-toolbar") {
            fontSize = 0.px
            // Hack to remove whitespace that results from using inline-block
            marginTop = vars.baseLineHeight / 2
            marginBottom = vars.baseLineHeight / 2
            child(".btn + .btn > .btn-group + .btn > .btn + .btn-group") {
                marginLeft = 5.px
            }
        }

        // Float them, remove border radius, then re-add to first and last elements
        rule(".btn-group > .btn") {
            position = Position.relative
            with(mixins) { borderRadius(0.px) }
        }

        rule(".btn-group > .btn + .btn") {
            marginLeft = -1.px
        }

        rule(".btn-group > .btn, .btn-group > .dropdown-menu, .btn-group > .popover") {
            fontSize = vars.baseFontSize
            // redeclare as part 2 of font-size inline-block hack
        }

        // Reset fonts for other sizes
        rule(".btn-group > .btn-mini") {
            fontSize = vars.fontSizeMini
        }

        rule(".btn-group > .btn-small") {
            fontSize = vars.fontSizeSmall
        }

        rule(".btn-group > .btn-large") {
            fontSize = vars.fontSizeLarge
        }

        // Set corners individual because sometimes a single button can be in a .btn-group and we need :first-child and :last-child to both match
        rule(".btn-group > .btn:first-child") {
            marginLeft = 0.px
            with(mixins) { borderTopLeftRadius(vars.baseBorderRadius) }
            with(mixins) { borderBottomLeftRadius(vars.baseBorderRadius) }
        }
        // Need .dropdown-toggle since :last-child doesn't apply given a .dropdown-menu immediately after it
        ".btn-group > .btn:last-child, .btn-group > .dropdown-toggle" {
            with(mixins) { borderTopRightRadius(vars.baseBorderRadius) }
            with(mixins) { borderBottomRightRadius(vars.baseBorderRadius) }
        }
        // Reset corners for large buttons
        rule(".btn-group > .btn.large:first-child") {
            marginLeft = 0.px
            with(mixins) { borderTopLeftRadius(vars.borderRadiusLarge) }
            with(mixins) { borderBottomLeftRadius(vars.borderRadiusLarge) }
        }

        rule(".btn-group > .btn.large:last-child, .btn-group > .large.dropdown-toggle") {
            with(mixins) { borderTopRightRadius(vars.borderRadiusLarge) }
            with(mixins) { borderBottomRightRadius(vars.borderRadiusLarge) }
        }

        // On hover/focus/active, bring the proper btn to front
        rule(".btn-group > .btn:hover, .btn-group > .btn:focus, .btn-group > .btn:active, .btn-group > .btn.active") {
            zIndex = 2
        }

        // On active and open, don't show outline
        rule(".btn-group .dropdown-toggle:active .btn-group.open .dropdown-toggle") {
            outlineWidth = 0.px
        }


        // Split button dropdowns

        // Give the line between buttons some depth
        rule(".btn-group > .btn + .dropdown-toggle") {
            paddingLeft = 8.px
            paddingRight = 8.px
            with(mixins) {
                boxShadow {
                    this += BoxShadowInset(rgb(255, 255, 255, 0.125), 1.px, 0.px, 0.px)
                    this += BoxShadowInset(rgb(255, 255, 255, 0.2), 0.px, 1.px, 0.px)
                    this += BoxShadow(rgb(0, 0, 0, 0.05), 0.px, 1.px, 2.px)
                }
            }
            declarations["*paddingTop"] = 5.px
            declarations["*paddingBottom"] = 5.px
        }

        rule(".btn-group > .btn-mini + .dropdown-toggle") {
            paddingLeft = 5.px
            paddingRight = 5.px
            declarations["*paddingTop"] = 2.px
            declarations["*paddingBottom"] = 2.px
        }

        rule(".btn-group > .btn-small + .dropdown-toggle") {
            declarations["*paddingTop"] = 5.px
            declarations["*paddingBottom"] = 4.px
        }

        rule(".btn-group > .btn-large + .dropdown-toggle") {
            paddingLeft = 12.px
            paddingRight = 12.px
            declarations["*paddingTop"] = 7.px
            declarations["*paddingBottom"] = 7.px
        }

        rule(".btn-group.open") {

            // The clickable button for toggling the menu
            // Remove the gradient and set the same inset shadow as the :active state
            ".dropdown-toggle" {
                backgroundImage = Image.none
                with(mixins) {
                    boxShadow {
                        this += BoxShadowInset(rgb(0, 0, 0, .15), 0.px, 2.px, 4.px)
                        this += BoxShadow(rgb(0, 0, 0, .05), 0.px, 1.px, 2.px)
                    }
                }
            }

            // Keep the hover's background when dropdown is open
            ".btn.dropdown-toggle" {
                backgroundColor = vars.btnBackgroundHighlight
            }
            ".btn-primary.dropdown-toggle" {
                backgroundColor = vars.btnPrimaryBackgroundHighlight
            }
            ".btn-warning.dropdown-toggle" {
                backgroundColor = vars.btnWarningBackgroundHighlight
            }
            ".btn-danger.dropdown-toggle" {
                backgroundColor = vars.btnDangerBackgroundHighlight
            }
            ".btn-success.dropdown-toggle" {
                backgroundColor = vars.btnSuccessBackgroundHighlight
            }
            ".btn-info.dropdown-toggle" {
                backgroundColor = vars.btnInfoBackgroundHighlight
            }
            ".btn-inverse.dropdown-toggle" {
                backgroundColor = vars.btnInverseBackgroundHighlight
            }
        }


        // Reposition the caret
        rule(".btn .caret") {
            marginTop = 8.px
            marginLeft = 0.px
        }
        // Carets in other button sizes
        rule(".btn-large .caret") {
            marginTop = 6.px
        }

        rule(".btn-large .caret") {
            borderLeftWidth = 5.px
            borderRightWidth = 5.px
            borderTopWidth = 5.px
        }

        rule(".btn-mini .caret, .btn-small .caret") {
            marginTop = 8.px
        }
        // Upside down carets for .dropup
        rule(".dropup .btn-large .caret") {
            borderBottomWidth = 5.px
        }


        // Account for other colors
        rule(".btn-primary, .btn-warning, .btn-danger, .btn-info, .btn-success, .btn-inverse") {
            ".caret" {
                borderTopColor = vars.white
                borderBottomColor = vars.white
            }
        }


        // Vertical button groups
        rule(".btn-group-vertical") {
            display = Display.inlineBlock // makes buttons only take up the width they need
            with(mixins) { ie7InlineBlock() }
        }

        rule(".btn-group-vertical > .btn") {
            display = Display.block
            float = Float.none
            maxWidth = 100.pct
            with(mixins) { borderRadius(0.px) }
        }

        rule(".btn-group-vertical > .btn + .btn") {
            marginLeft = 0.px
            marginTop = -1.px
        }

        rule(".btn-group-vertical > .btn:first-child") {
            with(mixins) { borderRadius(vars.baseBorderRadius, vars.baseBorderRadius, 0.px, 0.px) }
        }

        rule(".btn-group-vertical > .btn:last-child") {
            with(mixins) { borderRadius(0.px, 0.px, vars.baseBorderRadius, vars.baseBorderRadius) }
        }

        rule(".btn-group-vertical > .btn-large:first-child") {
            with(mixins) { borderRadius(vars.borderRadiusLarge, vars.borderRadiusLarge, 0.px, 0.px) }
        }

        rule(".btn-group-vertical > .btn-large:last-child") {
            with(mixins) { borderRadius(0.px, 0.px, vars.borderRadiusLarge, vars.borderRadiusLarge) }
        }
    }


    override fun CssBuilder.buttons() {
        // Base styles

        // Core
        rule(".btn") {
            display = Display.inlineBlock
            with(mixins) { ie7InlineBlock() }
            padding = Padding(4.px, 12.px)
            marginBottom = 0.px // For input.btn
            fontSize = vars.baseFontSize
            lineHeight = vars.baseLineHeight.lh
            textAlign = TextAlign.center
            verticalAlign = VerticalAlign.middle
            cursor = Cursor.pointer
            with(mixins) {
                buttonBackground(
                    startColor = vars.btnBackground,
                    endColor = vars.btnBackgroundHighlight,
                    textColor = vars.grayDark,
                    textShadow = "0 px 1 px 1 px rgba(255, 255, 255, .75)"
                )
            }
            border = Border(1.px, BorderStyle.solid, vars.btnBorder)
            declarations["*border"] = "0px"
            // Remove the border to prevent IE7's black border on input:focus
            borderBottomColor = vars.btnBorder.darken(10)
            with(mixins) { borderRadius(vars.baseBorderRadius) }
            with(mixins) { ie7RestoreLeftWhitespace() }
            // Give IE7 some love
            with(mixins) {
                boxShadow {
                    this += BoxShadowInset(rgb(255, 255, 255, .2), 0.px, 1.px, 0.px)
                    this += BoxShadow(rgb(0, 0, 0, .05), 0.px, 1.px, 2.px)
                }
            }

            // Hover/focus state
            "&:hover, &:focus" {
                color = vars.grayDark
                textDecoration = TextDecoration.none
                backgroundPosition = RelativePosition("0px 15px")

                // transition is only when going to hover/focus, otherwise the background
                // behind the gradient (there for IE<=9 fallback) gets mismatched
                with(mixins) { transition("background-position", 0.1.s, Timing.linear) }

            }

            // Focus state for keyboard and accessibility
            focus {
                with(mixins) { tabFocus() }
            }

            // Active state
            "&.active, &:active" {
                backgroundImage = Image.none
                outlineWidth = 0.px
                with(mixins) {
                    boxShadow {
                        this += BoxShadowInset(rgb(0, 0, 0, .15), 0.px, 2.px, 4.px)
                        this += BoxShadow(rgb(0, 0, 0, 0.05), 0.px, 1.px, 2.px)
                    }
                }
            }

            // Disabled state
            "&.disabled, &[disabled]" {
                cursor = Cursor.default
                backgroundImage = Image.none
                with(mixins) { opacity(65) }
                with(mixins) { boxShadow {} }
            }

        }


        // Button Sizes

        // Large
        rule(".btn-large") {
            padding = vars.paddingLarge
            fontSize = vars.fontSizeLarge
            with(mixins) { borderRadius(vars.borderRadiusLarge) }
        }

        rule(".btn-large [class^=\"icon-\"], .btn-large [class*=\" icon-\"]") {
            marginTop = 4.px
        }

        // Small
        rule(".btn-small") {
            padding = vars.paddingSmall
            fontSize = vars.fontSizeSmall
            with(mixins) { borderRadius(vars.borderRadiusSmall) }
        }

        rule(".btn-small [class^=\"icon-\"], .btn-small [class*=\" icon-\"]") {
            marginTop = 0.px
        }

        rule(".btn-mini [class^=\"icon-\"], .btn-mini [class*=\" icon-\"]") {
            marginTop = -1.px
        }

        // Mini
        rule(".btn-mini") {
            padding = vars.paddingMini
            fontSize = vars.fontSizeMini
            with(mixins) { borderRadius(vars.borderRadiusSmall) }
        }


        // Block button
        rule(".btn-block") {
            display = Display.block
            width = 100.pct
            paddingLeft = 0.px
            paddingRight = 0.px
            with(mixins) { boxSizing(BoxSizing.borderBox) }
        }

        // Vertically space out multiple block buttons
        rule(".btn-block + .btn-block") {
            marginTop = 5.px
        }

        // Specificity overrides
        rule("input[type=\"submit\"], input[type=\"reset\"], input[type=\"button\"]") {
            "&.btn-block" {
                width = 100.pct
            }
        }


        // Alternate buttons

        // Provide *some* extra contrast for those who can get it
        rule(".btn-primary.active, .btn-warning.active, .btn-danger.active, .btn-success.active, .btn-info.active, .btn-inverse.active") {
            color = rgb(255, 255, 255, .75)
        }

        // Set the backgrounds
        rule(".btn-primary") {
            with(mixins) { buttonBackground(vars.btnPrimaryBackground, vars.btnPrimaryBackgroundHighlight) }
        }
        // Warning appears are orange
        rule(".btn-warning") {
            with(mixins) { buttonBackground(vars.btnWarningBackground, vars.btnWarningBackgroundHighlight) }
        }
        // Danger and error appear as red
        rule(".btn-danger") {
            with(mixins) { buttonBackground(vars.btnDangerBackground, vars.btnDangerBackgroundHighlight) }
        }
        // Success appears as green
        rule(".btn-success") {
            with(mixins) { buttonBackground(vars.btnSuccessBackground, vars.btnSuccessBackgroundHighlight) }
        }
        // Info appears as a neutral blue
        rule(".btn-info") {
            with(mixins) { buttonBackground(vars.btnInfoBackground, vars.btnInfoBackgroundHighlight) }
        }
        // Inverse appears as dark gray
        rule(".btn-inverse") {
            with(mixins) { buttonBackground(vars.btnInverseBackground, vars.btnInverseBackgroundHighlight) }
        }


        // Cross-browser Jank
        rule("button.btn, input[type=\"submit\"].btn") {

            // Firefox 3.6 only I believe
            "&::-moz-focus-inner" {
                padding = Padding(0.px)
                borderWidth = 0.px
            }

            // IE7 has some default padding on button controls
            declarations["*paddingTop"] = 3.px
            declarations["*paddingBottom"] = 3.px
            rule("&.btn-large") {
                declarations["*paddingTop"] = 7.px
                declarations["*paddingBottom"] = 7.px
            }
            "&.btn-small" {
                declarations["*paddingTop"] = 3.px
                declarations["*paddingBottom"] = 3.px
            }
            "&.btn-mini" {
                declarations["*paddingTop"] = 1.px
                declarations["*paddingBottom"] = 1.px
            }
        }


        // Link buttons

        // Make a button look and behave like a link
        rule(".btn-link, .btn-link:active, .btn-link[disabled]") {
            backgroundColor = Color.transparent
            backgroundImage = Image.none
            with(mixins) { boxShadow { } }
        }

        rule(".btn-link") {
            borderColor = Color.transparent
            cursor = Cursor.pointer
            color = vars.linkColor
            with(mixins) { borderRadius(0.px) }
        }

        rule(".btn-link:hover, .btn-link:focus") {
            color = vars.linkColorHover
            textDecoration = TextDecoration(setOf(TextDecorationLine.underline))
            backgroundColor = Color.transparent
        }

        rule(".btn-link[disabled]:hover, .btn-link[disabled]:focus") {
            color = vars.grayDark
            textDecoration = TextDecoration.none
        }
    }


    override fun CssBuilder.carousel() {
        rule(".carousel") {
            position = Position.relative
            marginBottom = vars.baseLineHeight
            lineHeight = 1.px.lh
        }

        rule(".carousel-inner") {
            overflow = Overflow.hidden
            width = 100.pct
            position = Position.relative
        }

        rule(".carousel-inner") {
            rule("> .item") {
                display = Display.none
                position = Position.relative
                with(mixins) { transition(".6s ease-in-out left") }

                // Account for jankitude on images
                child("img > a > img") {
                    display = Display.block
                    lineHeight = 1.px.lh
                }
            }

            rule("> .active, > .next, > .prev") { display = Display.block }

            rule("> .active") {
                left = 0.px
            }

            rule("> .next, > .prev") {
                position = Position.absolute
                top = 0.px
                width = 100.pct
            }

            rule("> .next") {
                left = 100.pct
            }
            child(".prev") {
                left = -100.pct
            }
            child(".next.left, > .prev.right") {
                left = 0.px
            }

            rule("> .active.left") {
                left = -100.pct
            }
            child(".active.right") {
                left = 100.pct
            }

        }

        // Left/right controls for nav
        rule(".carousel-control") {
            position = Position.absolute
            top = 40.pct
            left = 15.px
            width = 40.px
            height = 40.px
            marginTop = -20.px
            fontSize = 60.px
            fontWeight = FontWeight.w100
            lineHeight = 30.px.lh
            color = vars.white
            textAlign = TextAlign.center
            backgroundColor = vars.grayDarker
            border = Border(3.px, BorderStyle.solid, vars.white)
            with(mixins) { borderRadius(23.px) }
            with(mixins) { opacity(50) }

            // we can't have this transition here
            // because webkit cancels the carousel
            // animation if you trip this while
            // in the middle of another animation
            // ;_
            // .transition(opacity .2s linear)

            // Reposition the right one
            "&.right" {
                left = LinearDimension.auto
                right = 15.px
            }

            // Hover/focus state
            "&:hover &:focus" {
                color = vars.white
                textDecoration = TextDecoration.none
                with(mixins) { opacity(0.90) }
            }
        }

        // Carousel indicator pips
        rule(".carousel-indicators") {
            position = Position.absolute
            top = 15.px
            right = 15.px
            zIndex = 5
            margin = Margin(0.px)
            listStyleType = ListStyleType.none
            rule("li") {
                display = Display.block
                float = Float.left
                width = 10.px
                height = 10.px
                marginLeft = 5.px
                declarations["textIndent"] = -999.px
                backgroundColor = Color("#ccc")
                backgroundColor = rgb(255, 255, 255, .25)
                borderRadius = 5.px
            }
            ".active" {
                backgroundColor = Color("#fff")
            }
        }

        // Caption for text below images
        rule(".carousel-caption") {
            position = Position.absolute
            left = 0.px
            right = 0.px
            bottom = 0.px
            padding = Padding(15.px)
            backgroundColor = vars.grayDark
            backgroundColor = rgb(0, 0, 0, .75)
        }

        rule(".carousel-caption h4, .carousel-caption p") {
            color = vars.white
            lineHeight = vars.baseLineHeight.lh
        }

        rule(".carousel-caption h4") {
            margin = Margin(0.px, 0.px, 5.px)
        }

        rule(".carousel-caption p") {
            marginBottom = 0.px
        }
    }


    override fun CssBuilder.close() {
        rule(".close") {
            float = Float.right
            fontSize = 20.px
            fontWeight = FontWeight.bold
            lineHeight = vars.baseLineHeight.lh
            color = vars.black
            declarations["text-shadow"] = "0px 1px 0px rgba(255,255,255,1)"
            with(mixins) { opacity(20) }
            "&:hover &:focus" {
                color = vars.black
                textDecoration = TextDecoration.none
                cursor = Cursor.pointer
                with(mixins) { opacity(40) }
            }
        }

        /**
         * Additional properties for button version.
         * iOS requires the button element instead of an anchor tag.
         * If you want the anchor version, it requires `href="#"`.
         */
        rule("button.close") {
            padding = Padding(0.px)
            cursor = Cursor.pointer
            backgroundColor = Color.transparent
            borderWidth = 0.px
            declarations["-webkit-appearance"] = "none"
        }
    }


    override fun CssBuilder.code() {
        // Inline and block code styles
        rule("code, pre") {
            padding = Padding(0.px, 3.px, 2.px)
            with(mixins) { fontFamilyMonospace() }

            fontSize = vars.baseFontSize-2.px
            color = vars.grayDark
            with(mixins) { borderRadius(3.px) }
        }

        // Inline code
        rule("code") {
            padding = Padding(2.px, 4.px)
            color = Color("#d14")
            backgroundColor = Color("#f7f7f9")
            border = Border(1.px, BorderStyle.solid, Color("#e1e1e8"))
            whiteSpace = WhiteSpace.nowrap
        }

        // Blocks of code
        rule("pre") {
            display = Display.block
            padding = Padding((vars.baseLineHeight-1.px) / 2)
            margin = Margin(0.px, 0.px, vars.baseLineHeight / 2)
            fontSize = vars.baseFontSize-1.px
            // 14px to 13px
            lineHeight = vars.baseLineHeight.lh
            wordBreak = WordBreak.breakAll
            wordWrap = WordWrap.breakWord
            whiteSpace = WhiteSpace.pre
            whiteSpace = WhiteSpace.preWrap
            backgroundColor = Color("#f5f5f5")
            border = Border(1.px, BorderStyle.solid, Color("#ccc"))
            // fallback for IE7-8
            border = Border(1.px, BorderStyle.solid, rgb(0, 0, 0, .15))
            with(mixins) { borderRadius(vars.baseBorderRadius) }

            // Make prettyprint styles more spaced out for readability
            "&.prettyprint" {
                marginBottom = vars.baseLineHeight
            }

            // Account for some code outputs that place code tags in pre tags
            code {
                padding = Padding(0.px)
                color = Color.inherit
                whiteSpace = WhiteSpace.pre
                whiteSpace = WhiteSpace.preWrap
                backgroundColor = Color.transparent
                borderWidth = 0.px
            }
        }

        // Enable scrollable blocks of code
        rule(".pre-scrollable") {
            maxHeight = 340.px
            overflowY = Overflow.scroll
        }
    }


    override fun CssBuilder.componentAnimations() {
        rule(".fade") {
            opacity = 0
            with(mixins) { transition("opacity .15s linear") }
            "&.in" {
                opacity = 1
            }
        }

        rule(".collapse") {
            position = Position.relative
            height = 0.px
            overflow = Overflow.hidden
            with(mixins) { transition("height .35s ease") }
            "&.in" {
                height = LinearDimension.auto
            }
        }
    }


    override fun CssBuilder.dropdowns() {
        // Use the .menu class on any <li> element within the topbar or ul.tabs and you'll get some superfancy dropdowns
        rule(".dropup, .dropdown") {
            position = Position.relative
        }

        rule(".dropdown-toggle") {
            // The caret makes the toggle a bit too tall in IE7
            declarations["*marginBottom"] = -3.px
        }

        rule(".dropdown-toggle:active, .open .dropdown-toggle") {
            outlineWidth = 0.px
        }

        // Dropdown arrow/caret
        rule(".caret") {
            display = Display.inlineBlock
            width = 0.px
            height = 0.px
            verticalAlign = VerticalAlign.top
            borderTop = Border(4.px, BorderStyle.solid, vars.black)
            borderRight = Border(4.px, BorderStyle.solid, Color.transparent)
            borderLeft = Border(4.px, BorderStyle.solid, Color.transparent)
            content = QuotedString("")
        }

        // Place the caret
        rule(".dropdown .caret") {
            marginTop = 8.px
            marginLeft = 2.px
        }

        // The dropdown menu (ul)
        rule(".dropdown-menu") {
            position = Position.absolute
            top = 100.pct
            left = 0.px
            zIndex = vars.zindexDropdown
            display = Display.none // none by default, but block on "open" of the menu
            float = Float.left
            minWidth = 160.px
            padding = Padding(5.px, 0.px)
            margin = Margin(2.px, 0.px, 0.px)
            // override default ul
            listStyleType = ListStyleType.none
            backgroundColor = vars.dropdownBackground
            border = Border(1.px, BorderStyle.solid, Color("#ccc"))
            // Fallback for IE7-8
            border = Border(1.px, BorderStyle.solid, vars.dropdownBorder)
            declarations["*border-right-width"] = "2px"
            declarations["*border-bottom-width"] = "2px"
            with(mixins) { borderRadius(6.px) }
            with(mixins) {
                boxShadow {
                    this += BoxShadow(rgb(0, 0, 0, 0.2), 0.px, 5.px, 10.px)
                }
            }
            declarations["-webkit-background-clip"] = BackgroundClip.paddingBox
            declarations["-moz-background-clip"] = BackgroundClip.paddingBox
            backgroundClip = BackgroundClip.paddingBox

            // Aligns the dropdown menu to right
            "&.pull-right" {
                right = 0.px
                left = LinearDimension.auto
            }

            // Dividers (basically an hr) within the dropdown
            ".divider" {
                with(mixins) { navDivider(vars.dropdownDividerTop, vars.dropdownDividerBottom) }
            }

            // Links within the dropdown menu
            child("li > a") {
                display = Display.block
                padding = Padding(3.px, 20.px)
                clear = Clear.both
                fontWeight = FontWeight.normal
                lineHeight = vars.baseLineHeight.lh
                color = vars.dropdownLinkColor
                whiteSpace = WhiteSpace.nowrap
            }
        }

        // Hover/Focus state
        rule(".dropdown-menu > li, > a:hover .dropdown-menu, > li > a:focus, .dropdown-submenu:hover > a, .dropdown-submenu:focus > a") {
            textDecoration = TextDecoration.none
            color = vars.dropdownLinkColorHover
            with(mixins) {
                gradientVertical(vars.dropdownLinkBackgroundHover, vars.dropdownLinkBackgroundHover.darken(5))
            }
        }

        // Active state
        rule(".dropdown-menu > .active, > a .dropdown-menu > .active > a:hover, .dropdown-menu, > .active > a:focus") {
            color = vars.dropdownLinkColorActive
            textDecoration = TextDecoration.none
            outlineWidth = 0.px
            with(mixins) {
                gradientVertical(vars.dropdownLinkBackgroundActive, vars.dropdownLinkBackgroundActive.darken(5))
            }
        }

        // Disabled state
        // Gray out text and ensure the hover/focus state remains gray
        rule(".dropdown-menu > .disabled > a, .dropdown-menu > .disabled > a:hover, .dropdown-menu > .disabled > a:focus") {
            color = vars.grayLight
        }
        // Nuke hover/focus effects
        rule(".dropdown-menu > .disabled > a:hover, .dropdown-menu > .disabled > a:focus") {
            textDecoration = TextDecoration.none
            backgroundColor = Color.transparent
            backgroundImage = Image.none
            // Remove CSS gradient
            with(mixins) { resetFilter() }
            cursor = Cursor.default
        }

        // Open state for the dropdown
        rule(".open") {
            // IE7's z-index only goes to the nearest positioned ancestor, which would
            // make the menu appear below buttons that appeared later on the page
            declarations["*z-index"] = "vars.zindexDropdown"
            rule("& > .dropdown-menu") {
                display = Display.block
            }
        }

        // Backdrop to catch body clicks on mobile, etc.
        rule(".dropdown-backdrop") {
            position = Position.fixed
            left = 0.px
            right = 0.px
            bottom = 0.px
            top = 0.px
            zIndex = vars.zindexDropdown-10
        }

        // Right aligned dropdowns
        rule(".pull-right > .dropdown-menu") {
            right = 0.px
            left = LinearDimension.auto
        }

        // Allow for dropdowns to go bottom up (aka, dropup-menu)
        // Just add .dropup after the standard .dropdown class and you're set, bro.
        // TODO: abstract this so that the navbar fixed styles are not placed here?
        rule(".dropup, .navbar-fixed-bottom .dropdown") {
            // Reverse the caret
            ".caret" {
                borderTopWidth = 0.px
                borderBottom = Border(4.px, BorderStyle.solid, vars.black)
                content = QuotedString("")
            }
            // Different positioning for bottom up menu
            ".dropdown-menu" {
                top = LinearDimension.auto
                bottom = 100.pct
                marginBottom = 1.px
            }
        }

        // Sub menus
        rule(".dropdown-submenu") {
            position = Position.relative
        }
        // Default dropdowns
        rule(".dropdown-submenu > .dropdown-menu") {
            top = 0.px
            left = 100.pct
            marginTop = -6.px
            marginLeft = -1.px
            with(mixins) { borderRadius(0.px, 6.px, 6.px, 6.px) }
        }

        rule(".dropdown-submenu:hover > .dropdown-menu") {
            display = Display.block
        }

        // Dropups
        rule(".dropup .dropdown-submenu > .dropdown-menu") {
            top = LinearDimension.auto
            bottom = 0.px
            marginTop = 0.px
            marginBottom = -2.px
            with(mixins) { borderRadius(5.px, 5.px, 5.px, 0.px) }
        }

        // Caret to indicate there is a submenu
        rule(".dropdown-submenu > a:after") {
            display = Display.block
            content = QuotedString(" ")
            float = Float.right
            width = 0.px
            height = 0.px

            borderColor = Color.transparent
            borderStyle = BorderStyle.solid
            borderWidth(5.px, 0.px, 5.px, 5.px)
            borderLeftColor = vars.dropdownBackground.darken(20)
            marginTop = 5.px
            marginRight = -10.px
        }

        rule(".dropdown-submenu:hover > a:after") {
            borderLeftColor = vars.dropdownLinkColorHover
        }

        // Left aligned submenus
        rule(".dropdown-submenu.pull-left") {
            // Undo the float
            // Yes, this is awkward since .pull-left adds a float, but it sticks to our conventions elsewhere.
            float = Float.none

            // Positioning the submenu
            child(".dropdown-menu") {
                left = -100.pct
                marginLeft = 10.px
                with(mixins) { borderRadius(6.px, 0.px, 6.px, 6.px) }
            }
        }

        // Tweak nav headers
        // Increase padding from 15px to 20px on sides
        rule(".dropdown .dropdown-menu .nav-header") {
            paddingLeft = 20.px
            paddingRight = 20.px
        }

        // Typeahead
        // ---------
        rule(".typeahead") {
            zIndex = 1051
            marginTop = 2.px // give it some space to breathe
            with(mixins) { borderRadius(vars.baseBorderRadius) }
        }
    }


    override fun CssBuilder.forms() {
        // GENERAL STYLES

        // Make all forms have space below them
        rule("form") {
            margin = Margin(0.px, 0.px, vars.baseLineHeight)
        }

        rule("fieldset") {
            padding = Padding(0.px)
            margin = Margin(0.px)
            borderWidth = 0.px
        }

        // Groups of fields with labels on top (legends)
        rule("legend") {
            display = Display.block
            width = 100.pct
            padding = Padding(0.px)
            marginBottom = vars.baseLineHeight
            fontSize = vars.baseFontSize * 1.5
            lineHeight = (vars.baseLineHeight * 2).lh
            color = vars.grayDark
            borderWidth = 0.px
            borderBottom = Border(1.px, BorderStyle.solid, Color("#e5e5e5"))

            // Small
            small {
                fontSize = vars.baseLineHeight * .75
                color = vars.grayLight
            }
        }

        // Set font for forms
        rule("label, input, button, select, textarea") {
            // Set size, weight, line-height here
            with(mixins) { fontShorthand(vars.baseFontSize, FontWeight.normal, vars.baseLineHeight.lh) }
        }

        ruleOf("input", "button", "select", "textarea") {
            fontFamily = vars.baseFontFamily
            // And only set font-family here for those that need it (note the missing label element)
        }

        // Identify controls by their labels
        rule("label") {
            display = Display.block
            marginBottom = 5.px
        }

        // Form controls

        // Shared size and type resets
        ruleOf(
            "select",
            "textarea",
            "input[type=\"text\"]",
            "input[type=\"password\"]",
            "input[type=\"datetime\"]",
            "input[type=\"datetime-local\"]",
            "input[type=\"date\"]",
            "input[type=\"month\"]",
            "input[type=\"time\"]",
            "input[type=\"week\"]",
            "input[type=\"number\"]",
            "input[type=\"email\"]",
            "input[type=\"url\"]",
            "input[type=\"search\"]",
            "input[type=\"tel\"]",
            "input[type=\"color\"]",
            ".uneditable-input"
        ) {
            display = Display.inlineBlock
            height = vars.baseLineHeight
            padding = Padding(4.px, 6.px)
            marginBottom = vars.baseLineHeight / 2
            fontSize = vars.baseFontSize
            lineHeight = vars.baseLineHeight.lh
            color = vars.gray
            with(mixins) { borderRadius(vars.inputBorderRadius) }
            verticalAlign = VerticalAlign.middle
        }

        // Reset appearance properties for textual inputs and textarea
        // Declare width for legacy (can't be on input[type=*] selectors or it's too specific)
        rule("input textarea .uneditable-input") {
            width = 206.px
            // plus 12px padding and 2px border
        }
        // Reset height since textareas have rows
        rule("textarea") {
            height = LinearDimension.auto
        }
        // Everything else
        ruleOf(
            "textarea",
            "input[type=\"text\"]",
            "input[type=\"password\"]",
            "input[type=\"datetime\"]",
            "input[type=\"datetime-local\"]",
            "input[type=\"date\"]",
            "input[type=\"month\"]",
            "input[type=\"time\"]",
            "input[type=\"week\"]",
            "input[type=\"number\"]",
            "input[type=\"email\"]",
            "input[type=\"url\"]",
            "input[type=\"search\"]",
            "input[type=\"tel\"]",
            "input[type=\"color\"]",
            ".uneditable-input"
        ) {
            backgroundColor = vars.inputBackground
            border = Border(1.px, BorderStyle.solid, vars.inputBorder)
            with(mixins) {
                boxShadow {
                    this += BoxShadowInset(rgb(0, 0, 0, .075), 0.px, 1.px, 1.px)
                }
                transition("border linear .2s, box-shadow linear .2s")
            }

            // Focus state
            "&:focus" {
                borderColor = rgb(82, 168, 236, .8)
                outlineWidth = 0.px
                declarations["outline"] = "thin dotted \\9;" /* IE6-9 */
                // IE6-9
                with(mixins) {
                    boxShadow {
                        this += BoxShadowInset(rgb(0, 0, 0, .075), 0.px, 1.px, 1.px)
                        this += BoxShadowInset(rgb(82, 168, 236, .6), 0.px, 0.px, 8.px)
                    }
                }
            }
        }

        // Position radios and checkboxes better
        "input[type=\"radio\"], input[type=\"checkbox\"]" {
            margin = Margin(4.px, 0.px, 0.px)
            declarations["*marginTop"] = "0.px" // IE7
            declarations["marginTop"] = "1px \\9" // IE8-9
            lineHeight = LineHeight.normal
        }

        // Reset width of input images, buttons, radios, checkboxes
        "input[type=\"file\"], input[type=\"image\"], input[type=\"submit\"], input[type=\"reset\"], input[type=\"button\"], input[type=\"radio\"], input[type=\"checkbox\"]" {
            width = LinearDimension.auto
            // Override of generic input selector
        }

        // Set the height of select and file controls to match text inputs
        rule("select, input[type=\"file\"]") {
            height =
                vars.inputHeight // In IE7, the height of the select element cannot be changed by height, only font-size
            declarations["*marginTop"] = "4.px" //  For IE7, add top margin to align select with labels
            lineHeight = vars.inputHeight.lh
        }

        // Make select elements obey height by applying a border
        rule("select") {
            width = 220.px
            // default input width + 10px of padding that doesn't get applied
            border = Border(1.px, BorderStyle.solid, vars.inputBorder)
            backgroundColor = vars.inputBackground
            // Chrome on Linux and Mobile Safari need background-color
        }

        // Make multiple select elements height not fixed
        rule("select[multiple], select[size]") {
            height = LinearDimension.auto
        }

        // Focus for select, file, radio, and checkbox
        rule("select:focus, input[type=\"file\"]:focus, input[type=\"radio\"]:focus, input[type=\"checkbox\"]:focus") {
            with(mixins) { tabFocus() }
        }


        // Uneditable inputs

        // Make uneditable inputs look inactive
        ruleOf(".uneditable-input", ".uneditable-textarea") {
            color = vars.grayLight
            backgroundColor = vars.inputBackground.darken(1)
            borderColor = vars.inputBorder
            with(mixins) { boxShadowInset(rgb(0, 0, 0, .025), 0.px, 1.px, 2.px) }
            cursor = Cursor.notAllowed
        }

        // For text that needs to appear as an input but should not be an input
        rule(".uneditable-input") {
            overflow = Overflow.hidden
            // prevent text from wrapping, but still cut it off like an input does
            whiteSpace = WhiteSpace.nowrap
        }

        // Make uneditable textareas behave like a textarea
        rule(".uneditable-textarea") {
            width = LinearDimension.auto
            height = LinearDimension.auto
        }


        // Placeholder

        // Placeholder text gets special styles because when browsers invalidate entire lines if it doesn't understand a selector
        ruleOf("input", "textarea") {
            with(mixins) { placeholder() }
        }


        // CHECKBOXES & RADIOS

        // Indent the labels to position radios/checkboxes as hanging
        rule(".radio .checkbox") {
            minHeight = vars.baseLineHeight
            // clear the floating input if there is no label text
            paddingLeft = 20.px
        }

        ruleOf(".radio input[type=\"radio\"]", ".checkbox input[type=\"checkbox\"]") {
            float = Float.left
            marginLeft = -20.px
        }

        // Move the options list down to align with labels
        ruleOf(".controls > .radio:first-child", ".controls > .checkbox:first-child") {
            paddingTop = 5.px // has to be padding because margin collaspes
        }

        // Radios and checkboxes on same line
        // TODO v3: Convert .inline to .control-inline
        ruleOf(".radio.inline", ".checkbox.inline") {
            display = Display.inlineBlock
            paddingTop = 5.px
            marginBottom = 0.px
            verticalAlign = VerticalAlign.middle
        }

        ruleOf(
            ".radio.inline + .radio.inline",
            ".checkbox.inline + .checkbox.inline"
        ) {
            marginLeft = 10.px // space out consecutive inline controls
        }


        // INPUT SIZES

        // General classes for quick sizes
        rule(".input-mini") { width = 60.px }

        rule(".input-small") { width = 90.px }

        rule(".input-medium") { width = 150.px }

        rule(".input-large") { width = 210.px }

        rule(".input-xlarge") { width = 270.px }

        rule(".input-xxlarge") { width = 530.px }

        // Grid style input sizes

// Redeclare since the fluid row class is more specific
        ruleOf(
            "input[class*=\"span\"],",
            "select[class*=\"span\"],",
            "textarea[class*=\"span\"],",
            ".uneditable-input[class*=\"span\"],",
            // Redeclare since the fluid row class is more specific
            ".row-fluid input[class*=\"span\"],",
            ".row-fluid select[class*=\"span\"],",
            ".row-fluid textarea[class*=\"span\"],",
            ".row-fluid .uneditable-input[class*=\"span\"]"
        ) {
            float = Float.none
            marginLeft = 0.px
        }

        // Ensure input-prepend/append never wraps
        ruleOf(
            ".input-append input[class*=\"span\"]",
            ".input-append .uneditable-input[class*=\"span\"]",
            ".input-prepend input[class*=\"span\"]",
            ".input-prepend .uneditable-input[class*=\"span\"]",
            ".row-fluid input[class*=\"span\"]",
            ".row-fluid select[class*=\"span\"]",
            ".row-fluid textarea[class*=\"span\"]",
            ".row-fluid .uneditable-input[class*=\"span\"]",
            ".row-fluid .input-prepend [class*=\"span\"]",
            ".row-fluid .input-append [class*=\"span\"]"
        ) {
            display = Display.inlineBlock
        }


        // GRID SIZING FOR INPUTS

        // Grid sizes
        with(mixins) { gridInput(vars.gridColumnWidth, vars.gridGutterWidth) {} }

        // Control row for multiple inputs per line
        rule(".controls-row") {
            with(mixins) { clearfix() }
            // Clear the float from controls
        }

        // Float to collapse white-space for proper grid alignment
        // Redeclare the fluid grid collapse since we undo the float for inputs
        ruleOf(
            ".controls-row [class*=\"span\"]",
            ".row-fluid .controls-row [class*=\"span\"]"
        ) {
            float = Float.left
        }
        // Explicity set top padding on all checkboxes/radios, not just first-child
        ruleOf(".controls-row .checkbox[class*=\"span\"]", ".controls-row .radio[class*=\"span\"]") {
            paddingTop = 5.px
        }


        // DISABLED STATE

        // Disabled and read-only inputs
        ruleOf(
            "input[disabled]",
            "select[disabled]",
            "textarea[disabled]",
            "input[readonly]",
            "select[readonly]",
            "textarea[readonly]"
        ) {
            cursor = Cursor.notAllowed
            backgroundColor = vars.inputDisabledBackground
        }
        // Explicitly reset the colors here
        ruleOf(
            "input[type=\"radio\"][disabled]",
            "input[type=\"checkbox\"][disabled]",
            "input[type=\"radio\"][readonly]",
            "input[type=\"checkbox\"][readonly]"
        ) {
            backgroundColor = Color.transparent
        }

        // FORM FIELD FEEDBACK STATES

        // Warning
        rule(".control-group.warning") {
            with(mixins) { formFieldState(vars.warningText, vars.warningText, vars.warningBackground) }
        }
        // Error
        rule(".control-group.error") {
            with(mixins) { formFieldState(vars.errorText, vars.errorText, vars.errorBackground) }
        }
        // Success
        rule(".control-group.success") {
            with(mixins) { formFieldState(vars.successText, vars.successText, vars.successBackground) }
        }
        // Success
        rule(".control-group.info") {
            with(mixins) { formFieldState(vars.infoText, vars.infoText, vars.infoBackground) }
        }

        // HTML5 invalid states
        // Shares styles with the .control-group.error above
        ruleOf(
            "input:focus:invalid",
            "textarea:focus:invalid",
            "select:focus:invalid"
        ) {
            color = Color("#b94a48")
            borderColor = Color("#ee5f5b")
            "&:focus" {
                borderColor = Color("#ee5f5b").darken(10)

                with(mixins) {
                    boxShadow {
                        this += BoxShadow(Color("#ee5f5b").lighten(20), 0.px, 0.px, 6.px)
                    }
                }
            }
        }


        // FORM ACTIONS
        rule(".form-actions") {
            padding = Padding((vars.baseLineHeight - 1.px), 20.px, vars.baseLineHeight)
            marginTop = vars.baseLineHeight
            marginBottom = vars.baseLineHeight
            backgroundColor = vars.formActionsBackground
            borderTop = Border(1.px, BorderStyle.solid, Color("#e5e5e5"))
            with(mixins) { clearfix() }
            // Adding clearfix to allow for .pull-right button containers
        }


        // HELP TEXT
        // ---------
        ruleOf(".help-block", ".help-inline") {
            color = vars.textColor.lighten(15)
            // lighten the text some for contrast
        }

        rule(".help-block") {
            display = Display.block // account for any element using help-block
            marginBottom = vars.baseLineHeight / 2
        }

        rule(".help-inline") {
            display = Display.inlineBlock
            with(mixins) { ie7InlineBlock() }
            verticalAlign = VerticalAlign.middle
            paddingLeft = 5.px
        }


        // INPUT GROUPS

        // Allow us to put symbols and text within the input field for a cleaner look
        ruleOf(".input-append", ".input-prepend") {
            display = Display.inlineBlock
            marginBottom = vars.baseLineHeight / 2
            verticalAlign = VerticalAlign.middle
            fontSize = 0.px
            // white space collapse hack
            whiteSpace = WhiteSpace.nowrap
            // Prevent span and input from separating

            // Reset the white space collapse hack
            ruleOf("input", "select", ".uneditable-input", ".dropdown-menu", ".popover") {
                fontSize = vars.baseFontSize
            }

            ruleOf("input", "select", ".uneditable-input") {
                position = Position.relative
                // placed here by default so that on :focus we can place the input above the .add-on for full border and box-shadow goodness
                marginBottom = 0.px // prevent bottom margin from screwing up alignment in stacked forms
                declarations["*marginLeft"] = 0.px
                verticalAlign = VerticalAlign.top
                with(mixins) { borderRadius(0.px, vars.inputBorderRadius, vars.inputBorderRadius, 0.px) }
                // Make input on top when focused so blue border and shadow always show
                "&:focus" { zIndex = 2 }
            }
            ".add-on" {
                display = Display.inlineBlock
                width = LinearDimension.auto
                height = vars.baseLineHeight
                minWidth = 16.px
                padding = Padding(4.px, 5.px)
                fontSize = vars.baseFontSize
                fontWeight = FontWeight.normal
                lineHeight = vars.baseLineHeight.lh
                textAlign = TextAlign.center
                declarations["text-shadow"] = "0px 1px 0px vars.white"
                backgroundColor = vars.grayLighter
                border = Border(1.px, BorderStyle.solid, Color("#ccc"))
            }
            ruleOf(".add-on", ".btn", ".btn-group", ">", ".dropdown-toggle") {
                verticalAlign = VerticalAlign.top
                with(mixins) { borderRadius(0.px) }
            }
            ".active" {
                backgroundColor = vars.green.lighten(30)
                borderColor = vars.green
            }
        }

        rule(".input-prepend") {
            ruleOf(".add-on", ".btn") {
                marginRight = -1.px
            }
            ruleOf(".add-on:first-child", ".btn:first-child") {
                // FYI, `.btn:first-child` accounts for a button group that's prepended
                with(mixins) { borderRadius(vars.inputBorderRadius, 0.px, 0.px, vars.inputBorderRadius) }
            }
        }

        rule(".input-append") {
            ruleOf("input", "select", ".uneditable-input") {
                with(mixins) { borderRadius(vars.inputBorderRadius, 0.px, 0.px, vars.inputBorderRadius) }
                "+. btn-group.btn:last-child" {
                    with(mixins) { borderRadius(0.px, vars.inputBorderRadius, vars.inputBorderRadius, 0.px) }
                }
            }
            ".add-on .btn .btn-group" {
                marginLeft = -1.px
            }
            ".add-on:last-child .btn:last-child .btn-group:last-child > .dropdown-toggle" {
                with(mixins) { borderRadius(0.px, vars.inputBorderRadius, vars.inputBorderRadius, 0.px) }
            }
        }

        // Remove all border-radius for inputs with both prepend and append
        rule(".input-prepend.input-append") {
            ruleOf("input", "select", ".uneditable-input") {
                with(mixins) { borderRadius(0.px) }
                "+ .btn-group.btn" {
                    with(mixins) { borderRadius(0.px, vars.inputBorderRadius, vars.inputBorderRadius, 0.px) }
                }
            }
            ".add-on:first-child .btn:first-child" {
                marginRight = -1.px
                with(mixins) { borderRadius(vars.inputBorderRadius, 0.px, 0.px, vars.inputBorderRadius) }
            }
            ".add-on:last-child .btn:last-child" {
                marginLeft = -1.px
                with(mixins) { borderRadius(0.px, vars.inputBorderRadius, vars.inputBorderRadius, 0.px) }
            }
            ".btn-group:first-child" {
                marginLeft = 0.px
            }
        }


        // SEARCH FORM
        rule("input.search-query") {
            paddingRight = 14.px
            declarations["padding-right"] = "4px \\9"
            paddingLeft = 14.px
            //IE7-8 doesn 't have border-radius, so don' t indent the padding
            declarations["padding-left"] = "4px \\9"
            marginBottom = 0.px // Remove the default margin on all inputs
            with(mixins) { borderRadius(15.px) }
        }

        //Allow for input prepend / append in search forms
        ruleOf(
            ".form-search .input-append .search-query",
            ".form-search .input-prepend .search-query"
        ) {
            with(mixins) { borderRadius(0.px) }
            // Override due to specificity
        }

        rule(".form-search .input-append .search-query") {
            with(mixins) { borderRadius(14.px, 0.px, 0.px, 14.px) }
        }

        rule(".form-search .input-append .btn") {
            with(mixins) { borderRadius(0.px, 14.px, 14.px, 0.px) }
        }

        rule(".form-search .input-prepend .search-query") {
            with(mixins) { borderRadius(0.px, 14.px, 14.px, 0.px) }
        }

        rule(".form-search .input-prepend .btn") {
            with(mixins) { borderRadius(14.px, 0.px, 0.px, 14.px) }
        }


        // HORIZONTAL & VERTICAL FORMS

        // Common properties
        ruleOf(".form-search", ".form-inline", ".form-horizontal") {
            ruleOf("input", "textarea", "select", ".help-inline", ".uneditable-input", ".input-prepend", ".input-append") {
                display = Display.inlineBlock
                with(mixins) { ie7InlineBlock() }
                marginBottom = 0.px
                verticalAlign = VerticalAlign.middle
            }
            // Re-hide hidden elements due to specifity
            ".hide" {
                display = Display.none
            }
        }

        ruleOf(
            ".form-search label",
            ".form-inline label",
            ".form-search .btn-group",
            ".form-inline .btn-group"
        ) {
            display = Display.inlineBlock
        }

        // Remove margin for input-prepend/-append
        ruleOf(
            ".form-search .input-append",
            ".form-inline .input-append",
            ".form-search .input-prepend",
            ".form-inline .input-prepend"
        ) {
            marginBottom = 0.px
        }
        // Inline checkbox/radio labels (remove padding on left)
        ruleOf(
            ".form-search .radio",
            ".form-search .checkbox",
            ".form-inline .radio",
            ".form-inline .checkbox"
        ) {
            paddingLeft = 0.px
            marginBottom = 0.px
            verticalAlign = VerticalAlign.middle
        }
        // Remove float and margin, set to inline-block
        ruleOf(
            ".form-search .radio input[type=\"radio\"]",
            ".form-search .checkbox input[type=\"checkbox\"]",
            ".form-inline .radio input[type=\"radio\"]",
            ".form-inline .checkbox input[type=\"checkbox\"]"
        ) {
            float = Float.left
            marginRight = 3.px
            marginLeft = 0.px
        }


        // Margin to space out fieldsets
        rule(".control-group") {
            marginBottom = vars.baseLineHeight / 2
        }

        // Legend collapses margin, so next element is responsible for spacing
        rule("legend + .control-group") {
            marginTop = vars.baseLineHeight
            declarations["-webkit-margin-top-collapse"] = "separate"
        }

        // Horizontal-specific styles
        rule(".form-horizontal") {
            // Increase spacing between groups
            ".control-group" {
                marginBottom = vars.baseLineHeight
                with(mixins) { clearfix() }
            }
            // Float the labels left
            ".control-label" {
                float = Float.left
                width = vars.horizontalComponentOffset - 20.px
                paddingTop = 5.px
                textAlign = TextAlign.right
            }
            // Move over all input controls and content
            ".controls" {
                // Super jank IE7 fix to ensure the inputs in .input-append and input-prepend
                // don't inherit the margin of the parent, in this case .controls
                declarations["*display"] = Display.inlineBlock
                declarations["*paddingLeft"] = 20.px
                marginLeft = vars.horizontalComponentOffset
                declarations["*marginLeft"] = 0.px
                "&:first-child" {
                    declarations["*paddingLeft"] = vars.horizontalComponentOffset
                }
            }
            // Remove bottom margin on block level help text since that's accounted for on .control-group
            ".help-block" {
                marginBottom = 0.px
            }
            // And apply it only to .help-block instances that follow a form control
            ruleOf("input", "select", "textarea.uneditable-input", ".input-prepend", ".input-append") {
                "+ .help-block" {
                    marginTop = vars.baseLineHeight / 2
                }
            }
            // Move over buttons in .form-actions to align with .controls
            ".form-actions" {
                paddingLeft = vars.horizontalComponentOffset
            }
        }
    }


    override fun CssBuilder.grid() {
        with(mixins) {
            // Fixed (940px)
            gridCore(vars.gridColumnWidth, vars.gridGutterWidth)

            // Fluid (940px)
            gridFluid(vars.fluidGridColumnWidth, vars.fluidGridGutterWidth)
        }


        // Reset utility classes due to specificity
        ruleOf("[class*=\"span\"].hide", ".row-fluid [class*=\"span\"].hide") {
            display = Display.none
        }

        ruleOf("[class*=\"span\"].pull-right", ".row-fluid [class*=\"span\"].pull-right") {
            float = Float.right
        }
    }


    override fun CssBuilder.heroUnit(){
        rule(".hero-unit") {
            padding = Padding(60.px)
            marginBottom = 30.px
            fontSize = 18.px
            fontWeight = FontWeight.w200
            lineHeight = (vars.baseLineHeight * 1.5).lh
            color = vars.heroUnitLeadColor
            backgroundColor = vars.heroUnitBackground
            with(mixins) { borderRadius(6.px) }
            h1 {
                marginBottom = 0.px
                fontSize = 60.px
                lineHeight = 1.px.lh
                color = vars.heroUnitHeadingColor
                letterSpacing = -1.px
            }
            li {
                lineHeight = (vars.baseLineHeight * 1.5).lh
                // Reset since we specify in type.less
            }
        }
    }


    override fun CssBuilder.labelsBadges() {
        // Base classes
        ruleOf(".label", ".badge") {
            display = Display.inlineBlock
            padding = Padding(2.px, 4.px)
            fontSize = vars.baseFontSize * .846
            fontWeight = FontWeight.bold
            lineHeight = 14.px.lh
            // ensure proper line-height if floated
            color = vars.white
            verticalAlign = VerticalAlign.baseline
            whiteSpace = WhiteSpace.nowrap
            declarations["text-shadow"] = "0px -1px 0px rgb(0,0,0,.25)"
            backgroundColor = vars.grayLight
        }
        // Set unique padding and border-radii
        rule(".label") {
            with(mixins) { borderRadius(3.px) }
        }

        rule(".badge") {
            paddingLeft = 9.px
            paddingRight = 9.px
            with(mixins) { borderRadius(9.px) }
        }

        // Empty labels/badges collapse
        ruleOf(".label", ".badge") {
            "&:empty" {
                display = Display.none
            }
        }

        // Hover/focus state, but only for links
        a {
            ruleOf("&.label:hover", "&.label:focus", "&.badge:hover", "&.badge:focus") {
                color = vars.white
                textDecoration = TextDecoration.none
                cursor = Cursor.pointer
            }
        }

        // Colors
        // Only give background-color difference to links (and to simplify, we don't qualifty with `a` but [href] attribute)
        ruleOf(".label", ".badge") {
            // Important (red)
            "&-important" { backgroundColor = vars.errorText }
            "&-important[href]" { backgroundColor = vars.errorText.darken(10) }
            // Warnings (orange)
            "&-warning" { backgroundColor = vars.orange }
            "&-warning[href]" { backgroundColor = vars.orange.darken(10) }
            // Success (green)
            "&-success" { backgroundColor = vars.successText }
            "&-success[href]" { backgroundColor = vars.successText.darken(10) }
            // Info (turquoise)
            "&-info" { backgroundColor = vars.infoText }
            "&-info[href]" { backgroundColor = vars.infoText.darken(10) }
            // Inverse (black)
            "&-inverse" { backgroundColor = vars.grayDark }
            "&-inverse[href]" { backgroundColor = vars.grayDark.darken(10) }
        }

        // Quick fix for labels/badges in buttons
        rule(".btn") {
            ruleOf(".label", ".badge") {
                position = Position.relative
                top = -1.px
            }
        }

        rule(".btn-mini") {
            ruleOf(".label", ".badge") {
                top = 0.px
            }
        }
    }


    override fun CssBuilder.layouts(){
        // Container (centered, fixed-width layouts)
        rule(".container") {
            with(mixins) { containerFixed() }
        }

        // Fluid layouts (left aligned, with sidebar, min- & max-width content)
        rule(".container-fluid") {
            paddingRight = vars.gridGutterWidth
            paddingLeft = vars.gridGutterWidth
            with(mixins) { clearfix() }
        }
    }


    override fun CssBuilder.media() {
        // Common styles

        // Clear the floats
        ruleOf(".media", ".media-body") {
            overflow = Overflow.hidden
            declarations["*overflow"] = "visible"
            zoom = 1.0
        }

        // Proper spacing between instances of .media
        ruleOf(".media", ".media .media") {
            marginTop = 15.px
        }

        rule(".media:first-child") {
            marginTop = 0.px
        }

        // For images and videos, set to block
        rule(".media-object") {
            display = Display.block
        }

        // Reset margins on headings for tighter default spacing
        rule(".media-heading") {
            margin = Margin(0.px, 0.px, 5.px)
        }


        // Media image alignment
        rule(".media > .pull-left") {
            marginRight = 10.px
        }

        rule(".media > .pull-right") {
            marginLeft = 10.px
        }


        // Media list variation

        // Undo default ul/ol styles
        rule(".media-list") {
            marginLeft = 0.px
            listStyleType = ListStyleType.none
        }
    }


    override fun CssBuilder.modals() {
        // Background
        rule(".modal-backdrop") {
            position = Position.fixed
            top = 0.px
            right = 0.px
            bottom = 0.px
            left = 0.px
            zIndex = vars.zindexModalBackdrop
            backgroundColor = vars.black
            // Fade for backdrop
            "&.fade" { opacity = 0 }
        }

        ruleOf(".modal-backdrop", ".modal-backdrop.fade.in") {
            with(mixins) { opacity(80.0) }
        }

        // Base modal
        rule(".modal") {
            position = Position.fixed
            top = 10.pct
            left = 50.pct
            zIndex = vars.zindexModal
            width = 560.px
            marginLeft = -280.px
            backgroundColor = vars.white
            border = Border(1.px, BorderStyle.solid, Color("#999"))
            border = Border(1.px, BorderStyle.solid, rgb(0, 0, 0, .3))
            declarations["*border"] = Border(1.px, BorderStyle.solid, Color("#999")) // IE6-7
            with(mixins) { borderRadius(6.px) }
            with(mixins) { boxShadow(0.px, 3.px, 7.px, rgb(0, 0, 0, 0.3)) }
            with(mixins) { backgroundClip(BackgroundClip.paddingBox) }
            // Remove focus outline from opened modal
            outlineStyle = OutlineStyle.none
            rule("&.fade") {
                with(mixins) { transition("e('opacity .3s linear, top .3s ease-out')") }
                top = -25.pct
            }
            "&.fade.in" { top = 10.pct }
        }

        rule(".modal-header") {
            padding = Padding(9.px, 15.px)
            borderBottom = Border(1.px, BorderStyle.solid, Color("#eee"))
            // Close icon
            ".close" { marginTop = 2.px }
            // Heading
            h3 {
                margin = Margin(0.px)
                lineHeight = 30.px.lh
            }
        }

        // Body (where all modal content resides)
        rule(".modal-body") {
            position = Position.relative
            overflowY = Overflow.auto
            maxHeight = 400.px
            padding = Padding(15.px)
        }
        // Remove bottom margin if need be
        rule(".modal-form") {
            marginBottom = 0.px
        }

        // Footer (for actions)
        rule(".modal-footer") {
            padding = Padding(14.px, 15.px, 15.px)
            marginBottom = 0.px
            textAlign = TextAlign.right
            // right align buttons
            backgroundColor = Color("#f5f5f5")
            borderTop = Border(1.px, BorderStyle.solid, Color("#ddd"))
            with(mixins) { borderRadius(0.px, 0.px, 6.px, 6.px) }
            with(mixins) { boxShadowInset(0.px, 1.px, 0.px, vars.white) }
            with(mixins) { clearfix() }
            // clear it in case folks use .pull-* classes on buttons

            // Properly space out buttons
            ".btn + .btn" {
                marginLeft = 5.px
                marginBottom =
                    0.px // account for input[type="submit"] which gets the bottom margin like all other inputs
            }
            // but override that for button groups
            ".btn-group .btn + .btn" {
                marginLeft = -1.px
            }
            // and override it for block buttons as well
            ".btn-block + .btn-block" {
                marginLeft = 0.px
            }
        }
    }


    override fun CssBuilder.navbar(){
        // COMMON STYLES

        // Base class and wrapper
        rule(".navbar") {
            overflow = Overflow.visible
            marginBottom = vars.baseLineHeight

            // Fix for IE7's bad z-indexing so dropdowns don't appear below content that follows the navbar
            declarations["*position"] = "relative"
            declarations["*z-index"] = "2"
        }

        // Inner for background effects
        // Gradient is applied to its own element because overflow visible is not honored by IE when filter is present
        rule(".navbar-inner") {
            minHeight = vars.navbarHeight
            paddingLeft = 20.px
            paddingRight = 20.px
            with(mixins) {
                gradientVertical(vars.navbarBackgroundHighlight, vars.navbarBackground)
            }
            border = Border(1.px, BorderStyle.solid, vars.navbarBorder)
            with(mixins) {
                borderRadius(vars.baseBorderRadius)
                boxShadow(0.px, 1.px, 4.px, rgb(0,0,0,.065))
            }

            // Prevent floats from breaking the navbar
            with(mixins) { clearfix() }
        }

        // Set width to auto for default container
        // We then reset it for fixed navbars in the #gridSystem mixin
        rule(".navbar .container") {
            width = LinearDimension.auto
        }

        // Override the default collapsed state
        rule(".nav-collapse.collapse") {
            height = LinearDimension.auto
            overflow = Overflow.visible
        }


        // Brand: website or project name
        rule(".navbar .brand") {
            float = Float.left
            display = Display.block
            // Vertically center the text given vars.navbarHeight
            padding =
                Padding(((vars.navbarHeight - vars.baseLineHeight) / 2), 20.px, ((vars.navbarHeight - vars.baseLineHeight) / 2))
            marginLeft = -20.px
            // negative indent to left-align the text down the page
            fontSize = 20.px
            fontWeight = FontWeight.w200
            color = vars.navbarBrandColor
            declarations["text-shadow"] = "0px 1px 0px vars.navbarBackgroundHighlight"
            ruleOf("&:hover", "&:focus") {
                textDecoration = TextDecoration.none
            }
        }

        // Plain text in topbar
        rule(".navbar-text") {
            marginBottom = 0.px
            lineHeight = vars.navbarHeight.lh
            color = vars.navbarText
        }

        // Janky solution for now to account for links outside the .nav
        rule(".navbar-link") {
            color = vars.navbarLinkColor
            ruleOf("&:hover", "&:focus") {
                color = vars.navbarLinkColorHover
            }
        }

        // Dividers in navbar
        rule(".navbar .divider-vertical") {
            height = vars.navbarHeight
            margin = Margin(0.px, 9.px)
            borderLeft = Border(1.px, BorderStyle.solid, vars.navbarBackground)
            borderRight = Border(1.px, BorderStyle.solid, vars.navbarBackgroundHighlight)
        }

        // Buttons in navbar
        ruleOf(".navbar .btn", ".navbar .btn-group") {
            with(mixins) { navbarVerticalAlign(30.px) }
            // Vertically center in navbar
        }

        ruleOf(".navbar .btn-group .btn",
               ".navbar .input-prepend .btn",
               ".navbar .input-append .btn",
               ".navbar .input-prepend .btn-group",
               ".navbar .input-append .btn-group") {
            marginTop = 0.px // then undo the margin here so we don't accidentally double it
        }

        // Navbar forms
        rule(".navbar-form") {
            marginBottom = 0.px // remove default bottom margin
            with(mixins) { clearfix() }

            ruleOf("input", "select", ".radio", ".checkbox") {
                with(mixins) { navbarVerticalAlign(30.px) }
                // Vertically center in navbar
            }

            ruleOf("input", "select", ".btn") {
                display = Display.inlineBlock
                marginBottom = 0.px
            }
            ruleOf("input[type=\"image\"]", "input[type=\"checkbox\"]", "input[type=\"radio\"]") {
                marginTop = 3.px
            }
            ruleOf(".input-append", ".input-prepend") {
                marginTop = 5.px
                whiteSpace = WhiteSpace.nowrap
                // preven two  items from separating within a .navbar-form that has .pull-left
                input {
                    marginTop = 0.px // remove the margin on top since it's on the parent
                }
            }
        }

        // Navbar search
        rule(".navbar-search") {
            position = Position.relative
            float = Float.left
            with(mixins) { navbarVerticalAlign(30.px) }
            // Vertically center in navbar
            marginBottom = 0.px
            ".search-query" {
                marginBottom = 0.px
                padding = Padding(4.px, 14.px)
//            #font > .sans-serif(13px, normal, 1)
                with(mixins) {
                    sansSerif(vars, FontWeight.normal, 13.px, LineHeight("1"))
                    borderRadius(15.px)
                }
                // redeclare because of specificity of the type attribute
            }
        }



        // Static navbar
        rule(".navbar-static-top") {
            position = Position.static
            marginBottom = 0.px // remove 18px margin for default navbar
            ".navbar-inner" {
                with(mixins) { borderRadius(0.px) }
            }
        }



        // Fixed navbar

        // Shared (top/bottom) styles
        ruleOf(".navbar-fixed-top", ".navbar-fixed-bottom") {
            position = Position.fixed
            right = 0.px
            left = 0.px
            zIndex = vars.zindexFixedNavbar
            marginBottom = 0.px // remove 18px margin for default navbar
        }

        ruleOf(".navbar-fixed-top .navbar-inner", ".navbar-static-top .navbar-inner") {
            borderWidth(0.px, 0.px, 1.px)
        }

        rule(".navbar-fixed-bottom .navbar-inner") {
            borderWidth(1.px, 0.px, 0.px)
        }

        ruleOf(".navbar-fixed-top .navbar-inner", ".navbar-fixed-bottom .navbar-inner") {
            paddingLeft = 0.px
            paddingRight = 0.px
            with(mixins) { borderRadius(0.px) }
        }

        // Reset container width
        // Required here as we reset the width earlier on and the grid mixins don't override early enough
        ruleOf(".navbar-static-top .container", ".navbar-fixed-top .container", ".navbar-fixed-bottom .container") {
            with (mixins) { gridCore { span(vars.gridColumns) }}

        }

        // Fixed to top
        rule(".navbar-fixed-top") {
            top = 0.px
        }

        ruleOf(".navbar-fixed-top", ".navbar-static-top") {
            ".navbar-inner" {
                with(mixins) { boxShadow(0.px, 1.px, 10.px, rgb(0, 0, 0, .1)) }
            }
        }

        // Fixed to bottom
        rule(".navbar-fixed-bottom") {
            bottom = 0.px
            ".navbar-inner" {
                with(mixins) { boxShadow(0.px, -1.px, 10.px, rgb(0, 0, 0, .1)) }
            }
        }



        // NAVIGATION
        rule(".navbar .nav") {
            position = Position.relative
            left = 0.px
            display = Display.block
            float = Float.left
            margin = Margin(0.px, 10.px, 0.px, 0.px)
        }

        rule(".navbar .nav.pull-right") {
            float = Float.right
            // redeclare due to specificity
            marginRight = 0.px // remove margin on float right nav
        }

        rule(".navbar .nav > li") {
            float = Float.left
        }

        // Links
        rule(".navbar .nav > li > a") {
            float = Float.none
            // Vertically center the text given vars.navbarHeight
            padding = Padding(((vars.navbarHeight-vars.baseLineHeight) / 2), 15.px, ((vars.navbarHeight-vars.baseLineHeight) / 2))
            color = vars.navbarLinkColor
            textDecoration = TextDecoration.none
            declarations["text-shadow"] = "0px 1px 0px vars.navbarBackgroundHighlight"
        }

        rule(".navbar .nav .dropdown-toggle .caret") {
            marginTop = 8.px
        }

        // Hover/focus
        ruleOf(".navbar .nav > li > a:focus", ".navbar .nav > li > a:hover") {
            backgroundColor = vars.navbarLinkBackgroundHover
            // "transparent" is default to differentiate :hover/:focus from .active
            color = vars.navbarLinkColorHover
            textDecoration = TextDecoration.none
        }

        // Active nav items
        ruleOf(".navbar .nav > .active > a", ".navbar .nav > .active > a:hover", ".navbar .nav > .active > a:focus") {
            color = vars.navbarLinkColorActive
            textDecoration = TextDecoration.none
            backgroundColor = vars.navbarLinkBackgroundActive
            with(mixins) { boxShadowInset( 0.px, 3.px, 8.px, rgb(0,0,0,.125)) }
        }

        // Navbar button for toggling navbar items in responsive layouts
        // These definitions need to come after '.navbar .btn'
        rule(".navbar .btn-navbar") {
            display = Display.none
            float = Float.right
            padding = Padding(7.px, 10.px)
            marginLeft = 5.px
            marginRight = 5.px
            with(mixins) { buttonBackground(vars.navbarBackgroundHighlight.darken(5), vars.navbarBackground.darken(5)) }
            with(mixins) {
                boxShadow {
                    this+=BoxShadowInset(rgb(255,255,255,.1), 0.px, 1.px, 0.px)
                    this+=BoxShadow(rgb(255,255,255,.075), 0.px, 1.px, 0.px)
                }
            }
        }

        rule(".navbar .btn-navbar .icon-bar") {
            display = Display.block
            width = 18.px
            height = 2.px
            backgroundColor = Color("#f5f5f5")
            with(mixins) {
                borderRadius(1.px)
                boxShadow(0.px, 1.px, 0.px, rgb(0,0,0,.25))
            }
        }

        rule(".btn-navbar .icon-bar + .icon-bar") {
            marginTop = 3.px
        }



        // Dropdown menus

        // Menu position and menu carets
        rule(".navbar .nav > li > .dropdown-menu") {
            "&:before" {
                content = QuotedString("")
                display = Display.inlineBlock
                borderLeft = Border(7.px, BorderStyle.solid, Color.transparent)
                borderRight = Border(7.px, BorderStyle.solid, Color.transparent)
                borderBottom = Border(7.px, BorderStyle.solid, Color("#ccc"))
                borderBottomColor = vars.dropdownBorder
                position = Position.absolute
                top = -7.px
                left = 9.px
            }
            "&:after" {
                content = QuotedString("")
                display = Display.inlineBlock
                borderLeft = Border(6.px, BorderStyle.solid, Color.transparent)
                borderRight = Border(6.px, BorderStyle.solid, Color.transparent)
                borderBottom = Border(6.px, BorderStyle.solid, vars.dropdownBackground)
                position = Position.absolute
                top = -6.px
                left = 10.px
            }
        }
        // Menu position and menu caret support for dropups via extra dropup class
        rule(".navbar-fixed-bottom .nav > li > .dropdown-menu") {
            "&:before" {
                borderTop = Border(7.px, BorderStyle.solid, Color("#ccc"))
                borderTopColor = vars.dropdownBorder
                borderBottomWidth = 0.px
                bottom = -7.px
                top = LinearDimension.auto
            }
            "&:after" {
                borderTop = Border(6.px, BorderStyle.solid, vars.dropdownBackground)
                borderBottomWidth = 0.px
                bottom = -6.px
                top = LinearDimension.auto
            }
        }

        // Caret should match text color on hover/focus
        ruleOf(".navbar .nav li.dropdown > a:hover .caret", ".navbar .nav li.dropdown > a:focus .caret") {
            borderTopColor = vars.navbarLinkColorHover
            borderBottomColor = vars.navbarLinkColorHover
        }

        // Remove background color from open dropdown
        ruleOf(".navbar .nav li.dropdown.open > .dropdown-toggle",
               ".navbar .nav li.dropdown.active > .dropdown-toggle",
               ".navbar .nav li.dropdown.open.active > .dropdown-toggle") {
            backgroundColor = vars.navbarLinkBackgroundActive
            color = vars.navbarLinkColorActive
        }

        rule(".navbar .nav li.dropdown > .dropdown-toggle .caret") {
            borderTopColor = vars.navbarLinkColor
            borderBottomColor = vars.navbarLinkColor
        }

        ruleOf(".navbar .nav li.dropdown.open > .dropdown-toggle .caret",
               ".navbar .nav li.dropdown.active > .dropdown-toggle .caret",
               ".navbar .nav li.dropdown.open.active > .dropdown-toggle .caret") {
            borderTopColor = vars.navbarLinkColorActive
            borderBottomColor = vars.navbarLinkColorActive
        }

        // Right aligned menus need alt position
        ruleOf(".navbar .pull-right > li > .dropdown-menu", ".navbar .nav > li > .dropdown-menu.pull-right") {
            left = LinearDimension.auto
            right = 0.px
            "&:before" {
                left = LinearDimension.auto
                right = 12.px
            }
            "&:after" {
                left = LinearDimension.auto
                right = 13.px
            }
            ".dropdown-menu" {
                left = LinearDimension.auto
                right = 100.pct
                marginLeft = 0.px
                marginRight = -1.px
                with(mixins) { borderRadius(6.px, 0.px, 6.px, 6.px) }
            }
        }


        // Inverted navbar
        rule(".navbar-inverse") {
            rule(".navbar-inner") {
                with(mixins) {
                    gradientVertical(vars.navbarInverseBackgroundHighlight, vars.navbarInverseBackground)
                }
                borderColor =  vars.navbarInverseBorder
            }

            ruleOf(".brand", ".nav > li > a") {
                color = vars.navbarInverseLinkColor
                declarations["text-shadow"] = "0px -1px 0px rgb(0,0,0,.25)"
                ruleOf("&:hover", "&:focus") {
                    color = vars.navbarInverseLinkColorHover
                }
            }

            rule(".brand") {
                color = vars.navbarInverseBrandColor
            }

            rule(".navbar-text") {
                color = vars.navbarInverseText
            }

            ruleOf(".nav > li > a:focus", ".nav > li > a:hover") {
                backgroundColor = vars.navbarInverseLinkBackgroundHover
                color = vars.navbarInverseLinkColorHover
            }

            ruleOf(".nav .active > a", ".nav .active > a:hover", ".nav .active > a:focus") {
                color = vars.navbarInverseLinkColorActive
                backgroundColor = vars.navbarInverseLinkBackgroundActive
            }

            // Inline text links
            ".navbar-link" {
                color = vars.navbarInverseLinkColor
                ruleOf("&:hover", "&:focus") {
                    color = vars.navbarInverseLinkColorHover
                }
            }

            // Dividers in navbar
            ".divider-vertical" {
                borderLeftColor = vars.navbarInverseBackground
                borderRightColor = vars.navbarInverseBackgroundHighlight
            }

            // Dropdowns
            ruleOf(".nav li.dropdown.open > .dropdown-toggle",
                   ".nav li.dropdown.active > .dropdown-toggle",
                   ".nav li.dropdown.open.active > .dropdown-toggle") {
                backgroundColor = vars.navbarInverseLinkBackgroundActive
                color = vars.navbarInverseLinkColorActive
            }
            ruleOf(".nav li.dropdown > a:hover .caret", ".nav li.dropdown > a:focus .caret") {
                borderTopColor = vars.navbarInverseLinkColorActive
                borderBottomColor = vars.navbarInverseLinkColorActive
            }
            ".nav li.dropdown > .dropdown-toggle .caret" {
                borderTopColor = vars.navbarInverseLinkColor
                borderBottomColor = vars.navbarInverseLinkColor
            }
            ruleOf(".nav li.dropdown.open > .dropdown-toggle .caret",
                   ".nav li.dropdown.active > .dropdown-toggle .caret",
                   ".nav li.dropdown.open.active > .dropdown-toggle .caret") {
                borderTopColor = vars.navbarInverseLinkColorActive
                borderBottomColor = vars.navbarInverseLinkColorActive
            }

            // Navbar search
            ".navbar-search" {
                ".search-query" {
                    color = vars.white
                    backgroundColor = vars.navbarInverseSearchBackground
                    borderColor =  vars.navbarInverseSearchBorder
                    with(mixins) {
                        boxShadow {
                            this+=BoxShadowInset(rgb(0,0,0,.1), 0.px, 1.px, 2.px)
                            this+=BoxShadow(rgb(255,255,255,.15), 0.px, 1.px, 0.px)
                        }
                        transition("none")
                        placeholder(vars.navbarInverseSearchPlaceholderColor)
                    }

                    // Focus states (we use .focused since IE7-8 and down doesn't support :focus)
                    ruleOf("&:focus", "&.focused") {
                        padding = Padding(5.px, 15.px)
                        color = vars.grayDark
                        declarations["text-shadow"] = "0px 1px 0px vars.white"
                        backgroundColor = vars.navbarInverseSearchBackgroundFocus
                        borderWidth = 0.px
                        with(mixins) { boxShadow(0.px, 0.px, 3.px, rgb(0,0,0,.15)) }
                        outlineWidth = 0.px
                    }
                }
            }

            // Navbar collapse button
            ".btn-navbar" {
                with(mixins) { buttonBackground(vars.navbarInverseBackgroundHighlight.darken(5), vars.navbarInverseBackground.darken(5)) }
            }

        }
    }


    override fun CssBuilder.navs() {
        // BASE CLASS
        rule(".nav") {
            marginLeft = 0.px
            marginBottom = vars.baseLineHeight
            listStyleType = ListStyleType.none
        }

        // Make links block level
        rule(".nav > li > a") {
            display = Display.block
        }

        ruleOf(".nav > li > a:hover", ".nav > li > a:focus") {
            textDecoration = TextDecoration.none
            backgroundColor = vars.grayLighter
        }

        // Prevent IE8 from misplacing imgs
        // See https://github.com/h5bp/html5-boilerplate/issues/984#issuecomment-3985989
        rule(".nav > li > a > img") {
            maxWidth = LinearDimension.none
        }

        // Redeclare pull classes because of specifity
        rule(".nav > .pull-right") {
            float = Float.right
        }

        // Nav headers (for dropdowns and lists)
        rule(".nav-header") {
            display = Display.block
            padding = Padding(3.px, 15.px)
            fontSize = 11.px
            fontWeight = FontWeight.bold
            lineHeight = vars.baseLineHeight.lh
            color = vars.grayLight
            declarations["text-shadow"] = "0px 1px 0px rgb(255,255,255,.5)"
            textTransform = TextTransform.uppercase
        }
        // Space them out when they follow another list item (link)
        rule(".nav li + .nav-header") {
            marginTop = 9.px
        }


        // NAV LIST
        // --------
        rule(".nav-list") {
            paddingLeft = 15.px
            paddingRight = 15.px
            marginBottom = 0.px
        }

        ruleOf(".nav-list > li > a", ".nav-list .nav-header") {
            marginLeft = -15.px
            marginRight = -15.px
            declarations["text-shadow"] = "0px 1px 0px rgb(255,255,255,.5)"
        }

        rule(".nav-list > li > a") {
            padding = Padding(3.px, 15.px)
        }

        ruleOf(".nav-list > .active > a", ".nav-list > .active > a:hover", ".nav-list > .active > a:focus") {
            color = vars.white
            declarations["text-shadow"] = "0px -1px 0px rgb(0,0,0,.2)"
            backgroundColor = vars.linkColor
        }

        ruleOf(".nav-list [class^=\"icon-\"]", ".nav-list [class*=\" icon-\"]") {
            marginRight = 2.px
        }
        // Dividers (basically an hr) within the dropdown
        rule(".nav-list .divider") {
            with(mixins) { navDivider() }
        }


        // TABS AND PILLS

        // Common styles
        ruleOf(".nav-tabs", ".nav-pills") {
            with(mixins) { clearfix() }
        }

        ruleOf(".nav-tabs > li", ".nav-pills > li") {
            float = Float.left
        }

        ruleOf(".nav-tabs > li > a", ".nav-pills > li > a") {
            paddingRight = 12.px
            paddingLeft = 12.px
            marginRight = 2.px
            lineHeight = 14.px.lh
            // keeps the overall height an even number
        }

        // TABS
        // ----

        // Give the tabs something to sit on
        rule(".nav-tabs") {
            borderBottom = Border(1.px, BorderStyle.solid, Color("#ddd"))
        }
        // Make the list-items overlay the bottom border
        rule(".nav-tabs > li") {
            marginBottom = -1.px
        }
        // Actual tabs (as links)
        rule(".nav-tabs > li > a") {
            paddingTop = 8.px
            paddingBottom = 8.px
            lineHeight = vars.baseLineHeight.lh
            border = Border(1.px, BorderStyle.solid, Color.transparent)
            with(mixins) { borderRadius(4.px, 4.px, 0.px, 0.px) }
            "&:hover &:focus" {
                borderColor = Color("${vars.grayLighter} ${vars.grayLighter} #ddd")
            }
        }
        // Active state, and it's :hover/:focus to override normal :hover/:focus
        ruleOf(".nav-tabs > .active > a", ".nav-tabs > .active > a:hover", ".nav-tabs > .active > a:focus") {
            color = vars.gray
            backgroundColor = vars.bodyBackground
            border = Border(1.px, BorderStyle.solid, Color("#ddd"))
            borderBottomColor = Color.transparent
            cursor = Cursor.default
        }


        // PILLS
        // -----

        // Links rendered as pills
        rule(".nav-pills > li > a") {
            paddingTop = 8.px
            paddingBottom = 8.px
            marginTop = 2.px
            marginBottom = 2.px
            with(mixins) { borderRadius(5.px) }
        }

        // Active state
        ruleOf(
            ".nav-pills > .active > a",
            ".nav-pills > .active > a:hover",
            ".nav-pills > .active > a:focus"
        ) {
            color = vars.white
            backgroundColor = vars.linkColor
        }


        // STACKED NAV

        // Stacked tabs and pills
        rule(".nav-stacked > li") {
            float = Float.none
        }

        rule(".nav-stacked > li > a") {
            marginRight = 0.px // no need for the gap between nav items
        }

        // Tabs
        rule(".nav-tabs.nav-stacked") {
            borderBottomWidth = 0.px
        }

        rule(".nav-tabs.nav-stacked > li > a") {
            border = Border(1.px, BorderStyle.solid, Color("#ddd"))
            with(mixins) { borderRadius(0.px) }
        }

        rule(".nav-tabs.nav-stacked > li:first-child > a") {
            with(mixins) { borderTopRadius(4.px) }
        }

        rule(".nav-tabs.nav-stacked > li:last-child > a") {
            with(mixins) { borderBottomRadius(4.px) }
        }

        ruleOf(".nav-tabs.nav-stacked > li > a:hover", ".nav-tabs.nav-stacked > li > a:focus") {
            borderColor = Color("#ddd")
            zIndex = 2
        }

        // Pills
        rule(".nav-pills.nav-stacked > li > a") {
            marginBottom = 3.px
        }

        rule(".nav-pills.nav-stacked > li:last-child > a") {
            marginBottom = 1.px // decrease margin to match sizing of stacked tabs
        }


        // DROPDOWNS
        // ---------
        rule(".nav-tabs .dropdown-menu") {
            with(mixins) { borderRadius(0.px, 0.px, 6.px, 6.px) }
            // remove the top rounded corners here since there is a hard edge above the menu
        }

        rule(".nav-pills .dropdown-menu") {
            with(mixins) { borderRadius(6.px) }
            // make rounded corners match the pills
        }

        // Default dropdown links
        // Make carets use linkColor to start
        rule(".nav .dropdown-toggle .caret") {
            borderTopColor = vars.linkColor
            borderBottomColor = vars.linkColor
            marginTop = 6.px
        }

        ruleOf(".nav .dropdown-toggle:hover .caret", ".nav .dropdown-toggle:focus .caret") {
            borderTopColor = vars.linkColorHover
            borderBottomColor = vars.linkColorHover
        }
        // move down carets for tabs
        rule(".nav-tabs .dropdown-toggle .caret") {
            marginTop = 8.px
        }

        // Active dropdown links
        rule(".nav .active .dropdown-toggle .caret") {
            borderTopColor = Color("#fff")
            borderBottomColor = Color("#fff")
        }

        rule(".nav-tabs .active .dropdown-toggle .caret") {
            borderTopColor = vars.gray
            borderBottomColor = vars.gray
        }

        // Active:hover/:focus dropdown links
        ruleOf(".nav > .dropdown.active > a:hover", ".nav > .dropdown.active > a:focus") {
            cursor = Cursor.pointer
        }

        // Open dropdowns
        ruleOf(
            ".nav-tabs .open .dropdown-toggle",
            ".nav-pills .open .dropdown-toggle",
            ".nav > li.dropdown.open.active > a:hover",
            ".nav > li.dropdown.open.active > a:focus"
        ) {
            color = vars.white
            backgroundColor = vars.grayLight
            borderColor = vars.grayLight
        }

        ruleOf(
            ".nav li.dropdown.open .caret",
            ".nav li.dropdown.open.active .caret",
            ".nav li.dropdown.open a:hover .caret",
            ".nav li.dropdown.open a:focus .caret"
        ) {
            borderTopColor = vars.white
            borderBottomColor = vars.white
            with(mixins) { opacity(100.0) }
        }

        // Dropdowns in stacked tabs
        ruleOf(".tabs-stacked .open > a:hover", ".tabs-stacked .open > a:focus") {
            borderColor = vars.grayLight
        }


        // TABBABLE
        // --------


        // COMMON STYLES

        // Clear any floats
        rule(".tabbable") {
            with(mixins) { clearfix() }
        }

        rule(".tab-content") {
            overflow = Overflow.auto
            // prevent content from running below tabs
        }

        // Remove border on bottom, left, right
        ruleOf(".tabs-below > .nav-tabs", ".tabs-right > .nav-tabs", ".tabs-left > .nav-tabs") {
            borderBottomWidth = 0.px
        }

        // Show/hide tabbable areas
        ruleOf(".tab-content > .tab-pane", ".pill-content > .pill-pane") {
            display = Display.none
        }

        ruleOf(".tab-content > .active", ".pill-content > .active") {
            display = Display.block
        }


        // BOTTOM
        // ------
        rule(".tabs-below > .nav-tabs") {
            borderTop = Border(1.px, BorderStyle.solid, Color("#ddd"))
        }

        rule(".tabs-below > .nav-tabs > li") {
            marginTop = -1.px
            marginBottom = 0.px
        }

        rule(".tabs-below > .nav-tabs > li > a") {
            with(mixins) { borderRadius(0.px, 0.px, 4.px, 4.px) }
            ruleOf("&:hover", "&:focus") {
                borderBottomColor = Color.transparent
                borderTopColor = Color("#ddd")
            }
        }

        ruleOf(
            ".tabs-below > .nav-tabs > .active > a",
            ".tabs-below > .nav-tabs > .active > a:hover",
            ".tabs-below > .nav-tabs > .active > a:focus"
        ) {
            borderColor = Color("transparent #ddd #ddd #ddd")
        }

        // LEFT & RIGHT

        // Common styles
        ruleOf(".tabs-left > .nav-tabs > li", ".tabs-right > .nav-tabs > li") {
            float = Float.none
        }

        ruleOf(".tabs-left > .nav-tabs > li > a", ".tabs-right > .nav-tabs > li > a") {
            minWidth = 74.px
            marginRight = 0.px
            marginBottom = 3.px
        }

        // Tabs on the left
        rule(".tabs-left > .nav-tabs") {
            float = Float.left
            marginRight = 19.px
            borderRight = Border(1.px, BorderStyle.solid, Color("#ddd"))
        }

        rule(".tabs-left > .nav-tabs > li > a") {
            marginRight = -1.px
            with(mixins) { borderRadius(4.px, 0.px, 0.px, 4.px) }
        }

        ruleOf(".tabs-left > .nav-tabs > li > a:hover", ".tabs-left > .nav-tabs > li > a:focus") {
            borderColor = Color("${vars.grayLighter} #ddd ${vars.grayLighter} ${vars.grayLighter}")
        }

        ruleOf(
            ".tabs-left > .nav-tabs .active > a",
            ".tabs-left > .nav-tabs .active > a:hover",
            ".tabs-left > .nav-tabs .active > a:focus"
        ) {
            borderColor = Color("#ddd transparent #ddd #ddd")
            declarations["*border-right-color"] = vars.white
        }

        // Tabs on the right
        rule(".tabs-right > .nav-tabs") {
            float = Float.right
            marginLeft = 19.px
            borderLeft = Border(1.px, BorderStyle.solid, Color("#ddd"))
        }

        rule(".tabs-right > .nav-tabs > li > a") {
            marginLeft = -1.px
            with(mixins) { borderRadius(0.px, 4.px, 4.px, 0.px) }
        }

        ruleOf(
            ".tabs-right > .nav-tabs > li > a:hover",
            ".tabs-right > .nav-tabs > li > a:focus"
        ) {
            borderColor = Color("${vars.grayLighter} ${vars.grayLighter} ${vars.grayLighter} #ddd")
        }

        ruleOf(
            ".tabs-right > .nav-tabs .active > a",
            ".tabs-right > .nav-tabs .active > a:hover",
            ".tabs-right > .nav-tabs .active > a:focus"
        ) {
            borderColor = Color("#ddd #ddd #ddd transparent")
            declarations["*border-left-color"] = vars.white
        }


        // DISABLED STATES

        // Gray out text
        rule(".nav > .disabled > a") {
            color = vars.grayLight
        }
        // Nuke hover/focus effects
        ruleOf(".nav > .disabled > a:hover", ".nav > .disabled > a:focus") {
            textDecoration = TextDecoration.none
            backgroundColor = Color.transparent
            cursor = Cursor.default
        }
    }


    override fun CssBuilder.pager() {
        rule(".pager") {
            margin = Margin(vars.baseLineHeight, 0.px)
            listStyleType = ListStyleType.none
            textAlign = TextAlign.center
            with(mixins) { clearfix() }
        }

        rule(".pager li") {
            display = Display.inline
        }

        ruleOf(".pager li > a", ".pager li > span") {
            display = Display.inlineBlock
            padding = Padding(5.px, 14.px)
            backgroundColor = Color("#fff")
            border = Border(1.px, BorderStyle.solid, Color("#ddd"))
            with(mixins) { borderRadius(15.px) }
        }

        ruleOf(".pager li > a:hover", ".pager li > a:focus") {
            textDecoration = TextDecoration.none
            backgroundColor = Color("#f5f5f5")
        }

        ruleOf(".pager .next > a", ".pager .next > span") {
            float = Float.right
        }

        ruleOf(".pager .previous > a", ".pager .previous > span") {
            float = Float.left
        }

        ruleOf(".pager .disabled > a", ".pager .disabled > a:hover", ".pager .disabled > a:focus", ".pager .disabled > span") {
            color = vars.grayLight
            backgroundColor = Color("#fff")
            cursor = Cursor.default
        }
    }


    override fun CssBuilder.pagination() {
        // Space out pagination from surrounding content
        rule(".pagination") {
            margin = Margin(vars.baseLineHeight, 0.px)
        }

        rule(".pagination ul") {
            // Allow for text-based alignment
            display = Display.inlineBlock
            with(mixins) { ie7InlineBlock() }
            // Reset default ul styles
            marginLeft = 0.px
            marginBottom = 0.px
            // Visuals
            with(mixins) {
                borderRadius(vars.baseBorderRadius)
                boxShadow(0.px, 1.px, 2.px, rgb(0, 0, 0, .05))
            }
        }

        rule(".pagination ul > li") {
            display = Display.inline // Remove list-style and block-level defaults
        }

        ruleOf(
            ".pagination ul > li > a",
            ".pagination ul > li > span"
        ) {
            float = Float.left
            // Collapse white-space
            padding = Padding(4.px, 12.px)
            lineHeight = vars.baseLineHeight.lh
            textDecoration = TextDecoration.none
            backgroundColor = vars.paginationBackground
            border = Border(1.px, BorderStyle.solid, vars.paginationBorder)
            borderLeftWidth = 0.px
        }

        ruleOf(
            ".pagination ul > li > a:hover",
            ".pagination ul > li > a:focus",
            ".pagination ul > .active > a",
            ".pagination ul > .active > span"
        ) {
            backgroundColor = vars.paginationActiveBackground
        }

        ruleOf(
            ".pagination ul > .active > a",
            ".pagination ul > .active > span"
        ) {
            color = vars.grayLight
            cursor = Cursor.default
        }

        ruleOf(
            ".pagination ul > .disabled > span",
            ".pagination ul > .disabled > a",
            ".pagination ul > .disabled > a:hover",
            ".pagination ul > .disabled > a:focus"
        ) {
            color = vars.grayLight
            backgroundColor = Color.transparent
            cursor = Cursor.default
        }

        ruleOf(
            ".pagination ul > li:first-child > a",
            ".pagination ul > li:first-child > span"
        ) {
            borderLeftWidth = 1.px
            with(mixins) { borderLeftRadius(vars.baseBorderRadius) }
        }

        ruleOf(
            ".pagination ul > li:last-child > a",
            ".pagination ul > li:last-child > span"
        ) {
            with(mixins) { borderRightRadius(vars.baseBorderRadius) }
        }


        // Alignment
        rule(".pagination-centered") {
            textAlign = TextAlign.center
        }

        rule(".pagination-right") {
            textAlign = TextAlign.right
        }


        // Sizing

        // Large
        rule(".pagination-large") {
            ruleOf("ul > li > a", "ul > li > span") {
                padding = vars.paddingLarge
                fontSize = vars.fontSizeLarge
            }
            ruleOf("ul > li:first-child > a", "ul > li:first-child > span") {
                with(mixins) { borderLeftRadius(vars.borderRadiusLarge) }
            }
            ruleOf("ul > li:last-child > a", "ul > li:last-child > span") {
                with(mixins) { borderRightRadius(vars.borderRadiusLarge) }
            }
        }

        // Small and mini
        ruleOf(".pagination-mini", ".pagination-small") {
            ruleOf("ul > li:first-child > a", "ul > li:first-child > span") {
                with(mixins) { borderLeftRadius(vars.borderRadiusSmall) }
            }
            ruleOf("ul > li:last-child > a", "ul > li:last-child > span") {
                with(mixins) { borderRightRadius(vars.borderRadiusSmall) }
            }
        }

        // Small
        rule(".pagination-small") {
            ruleOf("ul > li > a", "ul > li > span") {
                padding = vars.paddingSmall
                fontSize = vars.fontSizeSmall
            }
        }
        // Mini
        rule(".pagination-mini") {
            ruleOf("ul > li > a", "ul > li > span") {
                padding = vars.paddingMini
                fontSize = vars.fontSizeMini
            }
        }
    }


    override fun CssBuilder.popovers() {
        rule(".popover") {
            position = Position.absolute
            top = 0.px
            left = 0.px
            zIndex = vars.zindexPopover
            display = Display.none
            maxWidth = 276.px
            padding = Padding(1.px)
            textAlign = TextAlign.left
            // Reset given new insertion method
            backgroundColor = vars.popoverBackground

            declarations["-webkit-background-clip"] = BackgroundClip.paddingBox
            declarations["-moz-background-clip"] = "padding"
            backgroundClip = BackgroundClip.paddingBox

            border = Border(1.px, BorderStyle.solid, Color("#ccc"))
            border = Border(1.px, BorderStyle.solid, rgb(0, 0, 0, .2))
            with(mixins) {
                borderRadius(6.px)
                boxShadow(0.px, 5.px, 10.px, rgb(0, 0, 0, .2))
            }

            // Overrides for proper insertion
            whiteSpace = WhiteSpace.normal

            // Offset the popover to account for the popover arrow
            "&.top" { marginTop = -10.px }
            "&.right" { marginLeft = 10.px }
            "&.bottom" { marginTop = 10.px }
            "&.left" { marginLeft = -10.px }
        }

        rule(".popover-title") {
            margin = Margin(0.px) // reset heading margin
            padding = Padding(8.px, 14.px)
            fontSize = 14.px
            fontWeight = FontWeight.normal
            lineHeight = 18.px.lh
            backgroundColor = vars.popoverTitleBackground
            borderBottom = Border(1.px, BorderStyle.solid, vars.popoverTitleBackground.darken(5))
            with(mixins) { borderRadius(5.px, 5.px, 0.px, 0.px) }
            rule("&:empty") { display = Display.none }
        }

        rule(".popover-content") { padding = Padding(9.px, 14.px) }

        // Arrows
        //
        // .arrow is outer, .arrow:after is inner
        ruleOf(".popover .arrow", ".popover .arrow:after") {
            position = Position.absolute
            display = Display.block
            width = 0.px
            height = 0.px
            borderColor = Color.transparent
            borderStyle = BorderStyle.solid
        }

        rule(".popover .arrow") {
            borderWidth = vars.popoverArrowOuterWidth
        }

        rule(".popover .arrow:after") {
            borderWidth = vars.popoverArrowWidth
            content = QuotedString("")
        }

        rule(".popover") {
            "&.top .arrow" {
                left = 50.pct
                marginLeft = -vars.popoverArrowOuterWidth
                borderBottomWidth = 0.px
                borderTopColor = Color("#999") // IE8 fallback
                borderTopColor = vars.popoverArrowOuterColor
                bottom = -vars.popoverArrowOuterWidth
                "&:after" {
                    bottom = 1.px
                    marginLeft = -vars.popoverArrowWidth
                    borderBottomWidth = 0.px
                    borderTopColor = vars.popoverArrowColor
                }
            }
            "&.right .arrow" {
                top = 50.pct
                left = -vars.popoverArrowOuterWidth
                marginTop = -vars.popoverArrowOuterWidth
                borderLeftWidth = 0.px
                borderRightColor = Color("#999") // IE8 fallback
                borderRightColor = vars.popoverArrowOuterColor
                "&:after" {
                    left = 1.px
                    bottom = -vars.popoverArrowWidth
                    borderLeftWidth = 0.px
                    borderRightColor = vars.popoverArrowColor
                }
            }
            "&.bottom .arrow" {
                left = 50.pct
                marginLeft = -vars.popoverArrowOuterWidth
                borderTopWidth = 0.px
                borderBottomColor = Color("#999") // IE8 fallback
                borderBottomColor = vars.popoverArrowOuterColor
                top = -vars.popoverArrowOuterWidth
                "&:after" {
                    top = 1.px
                    marginLeft = -vars.popoverArrowWidth
                    borderTopWidth = 0.px
                    borderBottomColor = vars.popoverArrowColor
                }
            }

            rule("&.left .arrow") {
                top = 50.pct
                right = -vars.popoverArrowOuterWidth
                marginTop = -vars.popoverArrowOuterWidth
                borderRightWidth = 0.px
                borderLeftColor = Color("#999") // IE8 fallback
                borderLeftColor = vars.popoverArrowOuterColor
                "&:after" {
                    right = 1.px
                    borderRightWidth = 0.px
                    borderLeftColor = vars.popoverArrowColor
                    bottom = -vars.popoverArrowWidth
                }
            }

        }
    }


    override fun CssBuilder.progressBars() {
        // ANIMATIONS

        // Webkit
        rule("@-webkit-keyframes progress-bar-stripes") {
            "from" { backgroundPosition = RelativePosition("40px 0px") }
            "to" { backgroundPosition = RelativePosition("0px 0px") }
        }

        // Firefox
        rule("@-moz-keyframes progress-bar-stripes") {
            "from" { backgroundPosition = RelativePosition("40px 0px") }
            "to" { backgroundPosition = RelativePosition("0px 0px") }
        }

        // IE9
        rule("@-ms-keyframes progress-bar-stripes") {
            "from" { backgroundPosition = RelativePosition("40px 0px") }
            "to" { backgroundPosition = RelativePosition("0px 0px") }
        }

        // Opera
        rule("@-o-keyframes progress-bar-stripes") {
            "from" { backgroundPosition = RelativePosition("0px 0px") }
            "to" { backgroundPosition = RelativePosition("40px 0px") }
        }

        // Spec
        rule("@s.keyframes progress-bar-stripes") {
            "from" { backgroundPosition = RelativePosition("40px 0px") }
            "to" { backgroundPosition = RelativePosition("0px 0px") }
        }


        // THE BARS
        // --------

        // Outer container
        rule(".progress") {
            overflow = Overflow.hidden
            height = vars.baseLineHeight
            marginBottom = vars.baseLineHeight
            with(mixins) {
                gradientVertical(Color("#f5f5f5"), Color("#f9f9f9"))
                boxShadowInset(0.px, 1.px, 2.px, rgb(0, 0, 0, .1))
                borderRadius(vars.baseBorderRadius)
            }
        }

        // Bar of progress
        rule(".progress .bar") {
            width = 0.pct
            height = 100.pct
            color = vars.white
            float = Float.left
            fontSize = 12.px
            textAlign = TextAlign.center
            declarations["text-shadow"] = "0px -1px 0px rgb(0,0,0,.25)"
            with(mixins) {
                gradientVertical(Color("#149bdf"), Color("#0480be"))
                boxShadowInset(0.px, -1.px, 0.px, rgb(0, 0, 0, .15))
                boxSizing(BoxSizing.borderBox)
                transition("width .6s ease")
            }
        }

        rule(".progress .bar + .bar") {
            with(mixins) {
                boxShadow {
                    this += BoxShadowInset(rgb(0, 0, 0, .15), 1.px, 0.px, 0.px)
                    this += BoxShadow(rgb(0, 0, 0, .15), 0.px, -1.px, 0.px)
                }
            }
        }

        // Striped bars
        rule(".progress-striped .bar") {
            gradientStriped(Color("#149bdf"))

            with(mixins) { backgroundSize("40px 40px") }
        }

        // Call animation for the active one
        rule(".progress.active .bar") {
            declarations["-webkit-animation"] = "progress-bar-stripes 2s linear infinite"
            declarations["-moz-animation"] = "progress-bar-stripes 2s linear infinite"
            declarations["-ms-animation"] = "progress-bar-stripes 2s linear infinite"
            declarations["-o-animation"] = "progress-bar-stripes 2s linear infinite"
            animation += Animation("progress-bar-stripes", 2.s, Timing.linear, Time("infinite"))
        }


        // COLORS
        // ------

        // Danger (red)
        rule(".progress-danger .bar, .progress .bar-danger") {
            with(mixins) { gradientVertical(Color("#ee5f5b"), Color("#c43c35")) }
        }

        rule(".progress-danger.progress-striped .bar, .progress-striped .bar-danger") {
            with(mixins) { gradientVertical(Color("#ee5f5b")) }
        }

        // Success (green)
        rule(".progress-success .bar, .progress .bar-success") {
            with(mixins) { gradientVertical(Color("#62c462"), Color("#57a957")) }
        }

        rule(".progress-success.progress-striped .bar, .progress-striped .bar-success") {
            with(mixins) { gradientStriped(Color("#62c462")) }
        }

        // Info (teal)
        rule(".progress-info .bar, .progress .bar-info") {
            with(mixins) { gradientVertical(Color("#5bc0de"), Color("#339bb9")) }
        }

        rule(".progress-info.progress-striped .bar, .progress-striped .bar-info") {
            with(mixins) { gradientStriped(Color("#5bc0de")) }
        }

        // Warning (orange)
        rule(".progress-warning .bar, .progress .bar-warning") {
            with(mixins) { gradientVertical(vars.orange.lighten(15), vars.orange) }
        }

        rule(".progress-warning.progress-striped .bar, .progress-striped .bar-warning") {
            with(mixins) { gradientStriped(vars.orange.lighten(15)) }
        }
    }


    override fun CssBuilder.reset() {
        // Display in IE6-9 and FF3
        ruleOf("article", "aside", "details", "figcaption", "figure", "footer", "header", "hgroup", "nav", "section") {
            display = Display.block
        }

        // Display block in IE6-9 and FF3
        ruleOf("audio", "canvas", "video") {
            display = Display.inlineBlock
            declarations["*display"] = Display.inline
            declarations["*zoom"] = "1"
        }

        // Prevents modern browsers from displaying 'audio' without controls

        "audio:not([controls])" {
            display = Display.none
        }

        // Base settings
        rule("html") {
            fontSize = 100.pct
            declarations["-webkit-text-size-adjust"] = 100.pct
            declarations["-ms-text-size-adjust"] = 100.pct
        }
        // Focus states
        rule("a:focus") {
            with(mixins) { tabFocus() }
        }
        // Hover & Active
        ruleOf("a:hover", "a:active") {
            outlineWidth = 0.px
        }

        // Prevents sub and sup affecting line-height in all browsers
        ruleOf("sub", "sup") {
            position = Position.relative
            fontSize = 75.pct
            lineHeight = 0.px.lh
            verticalAlign = VerticalAlign.baseline
        }

        rule("sup") {
            top = -0.5.em
        }

        rule("sub") {
            bottom = -0.25.em
        }

        // Img border in a's and image quality
        rule("img") {
            // Responsive images (ensure images don't scale beyond their parents)
            maxWidth = 100.pct // Part 1: Set a maxium relative to the parent
            declarations["width"] = "auto\\9" // IE7-8 need help adjusting responsive images
            height =
                LinearDimension.auto // Part 2: Scale the height according to the width, otherwise you get stretching

            verticalAlign = VerticalAlign.middle
            borderWidth = 0.px
            declarations["-ms-interpolation-mode"] = "bicubic"
        }

        // Prevent max-width from affecting Google Maps
        ruleOf("#map_canvas img", ".google-maps img") {
            maxWidth = LinearDimension.none
        }

        // Forms

        // Font size in all browsers, margin changes, misc consistency
        ruleOf("button", "input", "select", "textarea") {
            margin = Margin(0.px)
            fontSize = 100.pct
            verticalAlign = VerticalAlign.middle
        }

        ruleOf("button", "input") {
            declarations["*overflow"] = "visible" // Inner spacing ie IE6/7
            lineHeight = LineHeight.normal // FF3/4 have !important on line-height in UA stylesheet
        }

        ruleOf("button::-moz-focus-inner", "input::-moz-focus-inner") { // Inner padding and border oddities in FF3/4
            padding = Padding(0.px)
            borderWidth = 0.px
        }

        ruleOf(
            "button",
            "html input[type=\"button\"]", // Avoid the WebKit bug in Android 4.0.* where (2) destroys native `audio` and `video` controls.
            "input[type=\"reset\"]",
            "input[type=\"submit\"]"
        ) {
            declarations["-webkit-appearance"] = button
            // Corrects inability to style clickable `input` types in iOS.
            cursor =
                Cursor.pointer // Improves usability and consistency of cursor style between image-type `input` and others.
        }

        ruleOf(
            "label",
            "select",
            "button",
            "input[type=\"button\"]",
            "input[type=\"reset\"]",
            "input[type=\"submit\"]",
            "input[type=\"radio\"]", "input[type=\"checkbox\"]"
        ) {
            cursor =
                Cursor.pointer // Improves usability and consistency of cursor style between image-type `input` and others.
        }

        rule("input[type=\"search\"]") { // Appearance in Safari/Chrome
            with(mixins) { boxSizing(BoxSizing.contentBox) }
            declarations["-webkit-appearance"] = "textfield"
        }

        ruleOf("input[type=\"search\"]::-webkit-search-decoration", "input[type=\"search\"]::-webkit-search-cancel-button") {
            declarations["-webkit-appearance"] = "none"
            // Inner-padding issues in Chrome OSX, Safari 5
        }

        rule("textarea") {
            overflow = Overflow.auto
            // Remove vertical scrollbar in IE6-9
            verticalAlign = VerticalAlign.top
            // Readability and alignment cross-browser
        }


        // Printing
        // Source: https://github.com/h5bp/html5-boilerplate/blob/master/css/main.css
        rule("@media print") {
            "*" {
                declarations["text-shadow"] = "none !important"
                color = Color("#000 !important") // Black prints faster: h5bp.com/s

                backgroundColor = Color("transparent !important")
                declarations["boxShadow"] = "none !important"
            }

            ruleOf("a", "a:visited") {
                textDecoration = TextDecoration(setOf(TextDecorationLine.underline))
            }

            rule("a[href]:after") {
                content = QuotedString("\" (\" attr(href) \")\"")
            }

            rule("abbr[title]:after") {
                content = QuotedString("\" (\" attr(title) \")\"")
            }

            // Don't show links for images, or javascript/internal links
            ruleOf(".ir a:after", "a[href^=\"javascript:\"]:after", "a[href^=\"#\"]:after") {
                content = QuotedString("")
            }

            ruleOf("pre", "blockquote") {
                border = Border(1.px, BorderStyle.solid, Color("#999"))
                declarations["page-break-inside"] = "avoid"
            }

            rule("thead") {
                display = Display.tableHeaderGroup // h5bp.com/t
            }

            ruleOf("tr", "img") {
                declarations["page-break-inside"] = "avoid"
            }

            rule("img") {
                maxWidth = LinearDimension("100% !important")
            }

            rule("vars.page") {
                margin = Margin(0.5.cm)
            }

            ruleOf("p", "h2", "h3") {
                declarations["orphans"] = 3
                declarations["widows"] = 3
            }

            ruleOf("h2", "h3") {
                declarations["page-break-inside"] = "avoid"
            }
        }
    }


    override fun CssBuilder.responsive1200pxMin() {
        media("(min-width: 1200px)") {

            with(mixins) {

                // Fixed grid
                gridCore(vars.gridColumnWidth1200, vars.gridGutterWidth1200)

                // Fluid grid
                gridFluid(vars.fluidGridColumnWidth1200, vars.fluidGridGutterWidth1200)

                // Input grid
                gridInput(vars.gridColumnWidth1200, vars.gridGutterWidth1200)
            }

            // Thumbnails
            ".thumbnails" {
                marginLeft = -vars.gridGutterWidth1200
            }
            ".thumbnails > li" {
                marginLeft = vars.gridGutterWidth1200
            }
            ".row-fluid .thumbnails" {
                marginLeft = 0.px
            }

        }
    }


    override fun CssBuilder.responsive767pxMax() {
        media("(max-width: 767px)") {

            // Padding to set content in a bit
            body {
                paddingLeft = 20.px
                paddingRight = 20.px
            }
            // Negative indent the now static "fixed" navbar
            ruleOf(".navbar-fixed-top", ".navbar-fixed-bottom", ".navbar-static-top") {
                marginLeft = -20.px
                marginRight = -20.px
            }
            // Remove padding on container given explicit padding set on body
            ".container-fluid" {
                padding = Padding(0.px)
            }

            // TYPOGRAPHY
            // ----------
            // Reset horizontal dl
            ".dl-horizontal" {
                dt {
                    float = Float.none
                    clear = Clear.none
                    width = LinearDimension.auto
                    textAlign = TextAlign.left
                }
                dd {
                    marginLeft = 0.px
                }
            }

            // GRID & CONTAINERS
            // -----------------
            // Remove width from containers
            ".container" {
                width = LinearDimension.auto
            }
            // Fluid rows
            ".row-fluid" {
                width = 100.pct
            }
            // Undo negative margin on rows and thumbnails
            ruleOf(".row", ".thumbnails") {
                marginLeft = 0.px
            }
            ".thumbnails > li" {
                float = Float.none
                marginLeft = 0.px // Reset the default margin for all li elements when no .span* classes are present
            }
            // Make all grid-sized elements block level again
            ruleOf(
                "[class*=\"span\"]",
                ".uneditable-input[class*=\"span\"]", // Makes uneditable inputs full-width when using grid sizing
                ".row-fluid [class*=\"span\"]"
            ) {
                float = Float.none
                display = Display.block
                width = 100.pct
                marginLeft = 0.px
                with(mixins) { boxSizing(BoxSizing.borderBox) }
            }
            ruleOf(".span12", ".row-fluid .span12") {
                width = 100.pct
                with(mixins) { boxSizing(BoxSizing.borderBox) }
            }
            ".row-fluid [class*=\"offset\"]:first-child" {
                marginLeft = 0.px
            }

            // FORM FIELDS
            // -----------
            // Make span* classes full width
            ruleOf(
                ".input-large",
                ".input-xlarge",
                ".input-xxlarge",
                "input[class*=\"span\"]",
                "select[class*=\"span\"]",
                "textarea[class*=\"span\"]",
                ".uneditable-input"
            ) {
                with(mixins) { inputBlockLevel() }
            }

            // But don't let it screw up prepend/append inputs
            ruleOf(
                ".input-prepend input",
                ".input-append input",
                ".input-prepend input[class*=\"span\"]",
                ".input-append input[class*=\"span\"]"
            ) {
                display = Display.inlineBlock // redeclare so they don't wrap to new lines
                width = LinearDimension.auto
            }
            ".controls-row [class*=\"span\"] + [class*=\"span\"]" {
                marginLeft = 0.px
            }

            // Modals
            ".modal" {
                position = Position.fixed
                top = 20.px
                left = 20.px
                right = 20.px
                width = LinearDimension.auto
                margin = Margin(0.px)
                "&.fade" { top = -100.px }
                "&.fade.in" { top = 20.px }
            }

        }


        // UP TO LANDSCAPE PHONE

        media("(max-width: 480px)") {

            // Smooth out the collapsing/expanding nav
            ".nav-collapse" {
                declarations["-webkit-transform"] = "translate3d(0, 0, 0px)"
                // activate the GPU
            }

            // Block level the page header small tag for readability
            ".page-header h1 small" {
                display = Display.block
                lineHeight = vars.baseLineHeight.lh
            }

            // Update checkboxes for iOS
            ruleOf("input[type=\"checkbox\"]", "input[type=\"radio\"]") {
                border = Border(1.px, BorderStyle.solid, Color("#ccc"))
            }

            // Remove the horizontal form styles
            ".form-horizontal" {
                ".control-label" {
                    float = Float.none
                    width = LinearDimension.auto
                    paddingTop = 0.px
                    textAlign = TextAlign.left
                }
                // Move over all input controls and content
                ".controls" {
                    marginLeft = 0.px
                }
                // Move the options list down to align with labels
                ".control-list" {
                    paddingTop = 0.px // has to be padding because margin collaspes
                }
                // Move over buttons in .form-actions to align with .controls
                ".form-actions" {
                    paddingLeft = 10.px
                    paddingRight = 10.px
                }
            }

            // Medias
            // Reset float and spacing to stack
            ruleOf(".media .pull-left", ".media .pull-right") {
                float = Float.none
                display = Display.block
                marginBottom = 10.px
            }
            // Remove side margins since we stack instead of indent
            ".media-object" {
                marginRight = 0.px
                marginLeft = 0.px
            }

            // Modals
            ".modal" {
                top = 10.px
                left = 10.px
                right = 10.px
            }
            ".modal-header .close" {
                padding = Padding(10.px)
                margin = Margin(-10.px)
            }

            // Carousel
            ".carousel-caption" {
                position = Position.static
            }

        }
    }


    override fun CssBuilder.responsive768px979px(){
        media("(min-width: 768px) and (max-width: 979px)") {
            with(mixins) {

                  // Fixed grid
                  gridCore(vars.gridColumnWidth768, vars.gridGutterWidth768)

                  // Fluid grid
                  gridFluid(vars.fluidGridColumnWidth768, vars.fluidGridGutterWidth768)

                  // Input grid
                  gridInput(vars.gridColumnWidth768, vars.gridGutterWidth768)

                  // No need to reset .thumbnails here since it's the same vars.gridGutterWidth
            }

        }
    }


    override fun CssBuilder.responsiveNavbar(){
        // TABLETS AND BELOW
        media("(max-width: vars.navbarCollapseWidth)") {

          // UNFIX THE TOPBAR
          // ----------------
          // Remove any padding from the body
          body {
            paddingTop = 0.px
          }
          // Unfix the navbars
          ruleOf(".navbar-fixed-top", ".navbar-fixed-bottom") {
            position = Position.static
          }
          ".navbar-fixed-top" {
            marginBottom = vars.baseLineHeight
          }
          ".navbar-fixed-bottom" {
            marginTop = vars.baseLineHeight
          }
          ruleOf(".navbar-fixed-top .navbar-inner", ".navbar-fixed-bottom .navbar-inner") {
            padding = Padding(5.px)
          }
          ".navbar .container" {
            width = LinearDimension.auto
            padding = Padding(0.px)
          }
          // Account for brand name
          ".navbar .brand" {
            paddingLeft = 10.px
            paddingRight = 10.px
            margin = Margin(0.px, 0.px, 0.px, -5.px)
          }

          // COLLAPSIBLE NAVBAR
          // ------------------
          // Nav collapse clears brand
          ".nav-collapse" {
            clear = Clear.both
          }
          // Block-level the nav
          ".nav-collapse .nav" {
            float = Float.none
            margin = Margin(0.px, 0.px, (vars.baseLineHeight / 2))
          }
          ".nav-collapse .nav > li" {
            float = Float.none
          }
          ".nav-collapse .nav > li > a" {
            marginBottom = 2.px
          }
          ".nav-collapse .nav > .divider-vertical" {
            display = Display.none
          }
          ".nav-collapse .nav .nav-header" {
            color = vars.navbarText
            declarations["textShadow"] = "none"
          }
          // Nav and dropdown links in navbar
          ruleOf(".nav-collapse .nav > li > a", ".nav-collapse .dropdown-menu a") {
            padding = Padding(9.px, 15.px)
            fontWeight = FontWeight.bold
            color = vars.navbarLinkColor
            with(mixins) { borderRadius(3.px) }
          }
          // Buttons
          ".nav-collapse .btn" {
            padding = Padding(4.px, 10.px, 4.px)
            fontWeight = FontWeight.normal
            with(mixins) { borderRadius(vars.baseBorderRadius) }
          }
          ".nav-collapse .dropdown-menu li + li a" {
            marginBottom = 2.px
          }
          ruleOf(".nav-collapse .nav > li > a:hover",
              ".nav-collapse .nav > li > a:focus",
              ".nav-collapse .dropdown-menu a:hover",
              ".nav-collapse .dropdown-menu a:focus") {
            backgroundColor = vars.navbarBackground
          }
          ruleOf(".navbar-inverse .nav-collapse .nav > li > a", ".navbar-inverse .nav-collapse .dropdown-menu a") {
            color = vars.navbarInverseLinkColor
          }
          ruleOf(".navbar-inverse .nav-collapse .nav > li > a:hover",
              ".navbar-inverse .nav-collapse .nav > li > a:focus",
              ".navbar-inverse .nav-collapse .dropdown-menu a:hover",
              ".navbar-inverse .nav-collapse .dropdown-menu a:focus") {
            backgroundColor = vars.navbarInverseBackground
          }
          // Buttons in the navbar
          ".nav-collapse.in .btn-group" {
            marginTop = 5.px
            padding = Padding(0.px)
          }
          // Dropdowns in the navbar
          ".nav-collapse .dropdown-menu" {
            position = Position.static
            top = LinearDimension.auto
            left = LinearDimension.auto
            float = Float.none
            display = Display.none
            maxWidth = LinearDimension.none
            margin = Margin(0.px, 15.px)
            padding = Padding(0.px)
            backgroundColor = Color.transparent
            borderStyle = BorderStyle.none
            with(mixins) {
                borderRadius(0.px)
                boxShadow(BoxShadows.none)
            }
          }
          ".nav-collapse .open > .dropdown-menu" {
            display = Display.block
          }

        ruleOf(".nav-collapse .dropdown-menu:before", ".nav-collapse .dropdown-menu:after") {
            display = Display.none
          }
          ".nav-collapse .dropdown-menu .divider" {
            display = Display.none
          }
          ".nav-collapse .nav > li > .dropdown-menu" {
            ruleOf("&:before", "&:after") {
              display = Display.none
            }
          }
          // Forms in navbar
          ruleOf(".nav-collapse .navbar-form", ".nav-collapse .navbar-search") {
            float = Float.none
            padding = Padding((vars.baseLineHeight / 2), 15.px)
            margin = Margin((vars.baseLineHeight / 2), 0.px)
            borderTop = Border(1.px, BorderStyle.solid, vars.navbarBackground)
            borderBottom = Border(1.px, BorderStyle.solid, vars.navbarBackground)
            with(mixins) {
                boxShadow {
                    this+=BoxShadowInset(rgb(255,255,255,.1), 0.px, 1.px, 0.px)
                    this+=BoxShadow(rgb(255,255,255,.1), 0.px, 1.px, 0.px)
                }
            }
          }
          ruleOf(".navbar-inverse .nav-collapse .navbar-form", ".navbar-inverse .nav-collapse .navbar-search") {
            borderTopColor = vars.navbarInverseBackground
            borderBottomColor = vars.navbarInverseBackground
          }
          // Pull right (secondary) nav content
          ".navbar .nav-collapse .nav.pull-right" {
            float = Float.none
            marginLeft = 0.px
          }
          // Hide everything in the navbar save .brand and toggle button
                 ruleOf(".nav-collapse", ".nav-collapse.collapse") {
                    overflow = Overflow.hidden
                    height = 0.px
                }
                    // Navbar button
                     rule(".navbar .btn-navbar") {
                    display = Display.block
                }

                    // STATIC NAVBAR
                    // -------------
                     rule(".navbar-static .navbar-inner") {
                    paddingLeft = 10.px
                    paddingRight = 10.px
                }


            }


        // DEFAULT DESKTOP

            media("(min-width: ${vars.navbarCollapseDesktopWidth})") {

                // Required to make the collapsing navbar work on regular desktops
                 rule(".nav-collapse.collapse") {
                    height = LinearDimension("auto !important")
                    declarations["overflow"] = "visible !important"
                }

            }
    }


    override fun CssBuilder.responsiveUtilities() {
        // IE10 Metro responsive
        // Required for Windows 8 Metro split-screen snapping with IE10
        // Source: http://timkadlec.com/2012/10/ie10-snap-mode-and-responsive-design/
        rule("@-ms-viewport") {
            width = LinearDimension("device-width")
        }

        // Hide from screenreaders and browsers
        // Credit: HTML5 Boilerplate
        rule(".hidden") {
            display = Display.none
            visibility = Visibility.hidden
        }

        // Visibility utilities

        // For desktops
        rule(".visible-phone") { declarations["display"] = "none !important" }

        rule(".visible-tablet") { declarations["display"] = "none !important" }

        rule(".hidden-phone") { }

        rule(".hidden-tablet") { }

        rule(".hidden-desktop") { declarations["display"] = "none !important" }

        rule(".visible-desktop") { declarations["display"] = "inherit !important" }

        // Tablets & small desktops only
        media("(min-width: 768px) and (max-width: 979px)") {
            // Hide everything else
            ".hidden-desktop" { declarations["display"] = "inherit !important" }
            ".visible-desktop" { declarations["display"] = "none !important " }
            // Show
            ".visible-tablet" { declarations["display"] = "inherit !important" }
            // Hide
            ".hidden-tablet" { declarations["display"] = "none !important" }
        }

        // Phones only
        media("(max-width: 767px)") {
            // Hide everything else
            ".hidden-desktop" { declarations["display"] = "inherit !important" }
            ".visible-desktop" { declarations["display"] = "none !important" }
            // Show
            ".visible-phone" {
                declarations["display"] = "inherit !important"
            } // Use inherit to restore previous behavior
            // Hide
            ".hidden-phone" { declarations["display"] = "none !important" }
        }

        // Print utilities
        rule(".visible-print") { declarations["display"] = "none !important" }

        rule(".hidden-print") { }

        rule("@media print") {
            ".visible-print" { declarations["display"] = "inherit !important" }
            ".hidden-print" { declarations["display"] = "none !important" }
        }
    }


    override fun CssBuilder.scaffolding(){
        // Body reset
        rule("body") {
          margin = Margin(0.px)
          fontFamily = vars.baseFontFamily
          fontSize = vars.baseFontSize
          lineHeight = vars.baseLineHeight.lh
          color = vars.textColor
          backgroundColor = vars.bodyBackground
        }


        // Links
        rule("a") {
          color = vars.linkColor
          textDecoration = TextDecoration.none
        }

        ruleOf("a:hover", "a:focus") {
          color = vars.linkColorHover
          textDecoration = TextDecoration(setOf(TextDecorationLine.underline))
        }


        // Images

        // Rounded corners
        rule(".img-rounded") {
          with(mixins) { borderRadius(6.px) }
        }

        // Add polaroid-esque trim
        rule(".img-polaroid") {
          padding = Padding(4.px)
          backgroundColor = Color("#fff")
          border = Border(1.px, BorderStyle.solid, Color("#ccc"))
          border = Border(1.px, BorderStyle.solid, rgb(0,0,0,.2))
          with(mixins) { boxShadow(0.px, 1.px, 3.px, rgb(0,0,0,.1)) }
        }

        // Perfect circle
        rule(".img-circle") {
          with(mixins) { borderRadius(500.px) }
         // crank the border-radius so it works with most reasonably sized images
        }
    }


    override fun CssBuilder.sprites(){
        // ICONS
        // -----

        // All icons receive the styles of the <i> tag with a base class
        // of .i and are then given a unique class to add width, height // and background-position. Your resulting HTML will look like
        // <i class="icon-inbox"></i>.

        // For the white version of the icons, just add the .icon-white class:
        // <i class="icon-inbox icon-white"></i>
        ruleOf("[class^=\"icon-\"]", "[class*=\" icon-\"]") {
          display = Display.inlineBlock
          width = 14.px
          height = 14.px
          with(mixins) { ie7RestoreRightWhitespace() }
          lineHeight = 14.px.lh
          verticalAlign = VerticalAlign.textTop
          backgroundImage = Image("url(\"@{iconSpritePath}\")")
          backgroundPosition = RelativePosition("14px 14px")
          backgroundRepeat = BackgroundRepeat.noRepeat
          marginTop = 1.px
        }

        // White icons with optional class, or on hover/focus/active states of certain elements
        ruleOf(".icon-white",
            ".nav-pills > .active > a > [class^=\"icon-\"]",
            ".nav-pills > .active > a > [class*=\" icon-\"]",
            ".nav-list > .active > a > [class^=\"icon-\"]",
            ".nav-list > .active > a > [class*=\" icon-\"]",
            ".navbar-inverse .nav > .active > a > [class^=\"icon-\"]",
            ".navbar-inverse .nav > .active > a > [class*=\" icon-\"]",
            ".dropdown-menu > li > a:hover > [class^=\"icon-\"]",
            ".dropdown-menu > li > a:focus > [class^=\"icon-\"]",
            ".dropdown-menu > li > a:hover > [class*=\" icon-\"]",
            ".dropdown-menu > li > a:focus > [class*=\" icon-\"]",
            ".dropdown-menu > .active > a > [class^=\"icon-\"]",
            ".dropdown-menu > .active > a > [class*=\" icon-\"]",
            ".dropdown-submenu:hover > a > [class^=\"icon-\"]",
            ".dropdown-submenu:focus > a > [class^=\"icon-\"]",
            ".dropdown-submenu:hover > a > [class*=\" icon-\"]",
            ".dropdown-submenu:focus > a > [class*=\" icon-\"]") {
          backgroundImage= Image("url(\"@{iconWhiteSpritePath}\")") }

        rule(".icon-glass") { backgroundPosition = RelativePosition("0px 0px") }
        rule(".icon-music") { backgroundPosition = RelativePosition("-24px 0px") }
        rule(".icon-search") { backgroundPosition = RelativePosition("-48px 0px") }
        rule(".icon-envelope") { backgroundPosition = RelativePosition("-72px 0px") }
        rule(".icon-heart") { backgroundPosition = RelativePosition("-96px 0px") }
        rule(".icon-star") { backgroundPosition = RelativePosition("-120px 0px") }
        rule(".icon-star-empty") { backgroundPosition = RelativePosition("-144px 0px") }
        rule(".icon-user") { backgroundPosition = RelativePosition("-168px 0px") }
        rule(".icon-film") { backgroundPosition = RelativePosition("-192px 0px") }
        rule(".icon-th-large") { backgroundPosition = RelativePosition("-216px 0px") }
        rule(".icon-th") { backgroundPosition = RelativePosition("-240px 0px") }
        rule(".icon-th-list") { backgroundPosition = RelativePosition("-264px 0px") }
        rule(".icon-ok") { backgroundPosition = RelativePosition("-288px 0px") }
        rule(".icon-remove") { backgroundPosition = RelativePosition("-312px 0px") }
        rule(".icon-zoom-in") { backgroundPosition = RelativePosition("-336px 0px") }
        rule(".icon-zoom-out") { backgroundPosition = RelativePosition("-360px 0px") }
        rule(".icon-off") { backgroundPosition = RelativePosition("-384px 0px") }
        rule(".icon-signal") { backgroundPosition = RelativePosition("-408px 0px") }
        rule(".icon-cog") { backgroundPosition = RelativePosition("-432px 0px") }
        rule(".icon-trash") { backgroundPosition = RelativePosition("-456px 0px") }

        rule(".icon-home") { backgroundPosition = RelativePosition("0px -24px") }
        rule(".icon-file") { backgroundPosition = RelativePosition("-24px -24px") }
        rule(".icon-time") { backgroundPosition = RelativePosition("-48px -24px") }
        rule(".icon-road") { backgroundPosition = RelativePosition("-72px -24px") }
        rule(".icon-download-alt") { backgroundPosition = RelativePosition("-96px -24px") }
        rule(".icon-download") { backgroundPosition = RelativePosition("-120px -24px") }
        rule(".icon-upload") { backgroundPosition = RelativePosition("-144px -24px") }
        rule(".icon-inbox") { backgroundPosition = RelativePosition("-168px -24px") }
        rule(".icon-play-circle") { backgroundPosition = RelativePosition("-192px -24px") }
        rule(".icon-repeat") { backgroundPosition = RelativePosition("-216px -24px") }
        rule(".icon-refresh") { backgroundPosition = RelativePosition("-240px -24px") }
        rule(".icon-list-alt") { backgroundPosition = RelativePosition("-264px -24px") }
        rule(".icon-lock") { backgroundPosition = RelativePosition("-287px -24px") } // 1px off
        rule(".icon-flag") { backgroundPosition = RelativePosition("-312px -24px") }
        rule(".icon-headphones") { backgroundPosition = RelativePosition("-336px -24px") }
        rule(".icon-volume-off") { backgroundPosition = RelativePosition("-360px -24px") }
        rule(".icon-volume-down") { backgroundPosition = RelativePosition("-384px -24px") }
        rule(".icon-volume-up") { backgroundPosition = RelativePosition("-408px -24px") }
        rule(".icon-qrcode") { backgroundPosition = RelativePosition("-432px -24px") }
        rule(".icon-barcode") { backgroundPosition = RelativePosition("-456px -24px") }

        rule(".icon-tag") { backgroundPosition = RelativePosition("0px -48px") }
        rule(".icon-tags") { backgroundPosition = RelativePosition("-25px -48px") } // 1px off
        rule(".icon-book") { backgroundPosition = RelativePosition("-48px -48px") }
        rule(".icon-bookmark") { backgroundPosition = RelativePosition("-72px -48px") }
        rule(".icon-print") { backgroundPosition = RelativePosition("-96px -48px") }
        rule(".icon-camera") { backgroundPosition = RelativePosition("-120px -48px") }
        rule(".icon-font") { backgroundPosition = RelativePosition("-144px -48px") }
        rule(".icon-bold") { backgroundPosition = RelativePosition("-167px -48px") } // 1px off
        rule(".icon-italic") { backgroundPosition = RelativePosition("-192px -48px") }
        rule(".icon-text-height") { backgroundPosition = RelativePosition("-216px -48px") }
        rule(".icon-text-width") { backgroundPosition = RelativePosition("-240px -48px") }
        rule(".icon-align-left") { backgroundPosition = RelativePosition("-264px -48px") }
        rule(".icon-align-center") { backgroundPosition = RelativePosition("-288px -48px") }
        rule(".icon-align-right") { backgroundPosition = RelativePosition("-312px -48px") }
        rule(".icon-align-justify") { backgroundPosition = RelativePosition("-336px -48px") }
        rule(".icon-list") { backgroundPosition = RelativePosition("-360px -48px") }
        rule(".icon-indent-left") { backgroundPosition = RelativePosition("-384px -48px") }
        rule(".icon-indent-right") { backgroundPosition = RelativePosition("-408px -48px") }
        rule(".icon-facetime-video") { backgroundPosition = RelativePosition("-432px -48px") }
        rule(".icon-picture") { backgroundPosition = RelativePosition("-456px -48px") }

        rule(".icon-pencil") { backgroundPosition = RelativePosition("0px -72px") }
        rule(".icon-map-marker") { backgroundPosition = RelativePosition("-24px -72px") }
        rule(".icon-adjust") { backgroundPosition = RelativePosition("-48px -72px") }
        rule(".icon-tint") { backgroundPosition = RelativePosition("-72px -72px") }
        rule(".icon-edit") { backgroundPosition = RelativePosition("-96px -72px") }
        rule(".icon-share") { backgroundPosition = RelativePosition("-120px -72px") }
        rule(".icon-check") { backgroundPosition = RelativePosition("-144px -72px") }
        rule(".icon-move") { backgroundPosition = RelativePosition("-168px -72px") }
        rule(".icon-step-backward") { backgroundPosition = RelativePosition("-192px -72px") }
        rule(".icon-fast-backward") { backgroundPosition = RelativePosition("-216px -72px") }
        rule(".icon-backward") { backgroundPosition = RelativePosition("-240px -72px") }
        rule(".icon-play") { backgroundPosition = RelativePosition("-264px -72px") }
        rule(".icon-pause") { backgroundPosition = RelativePosition("-288px -72px") }
        rule(".icon-stop") { backgroundPosition = RelativePosition("-312px -72px") }
        rule(".icon-forward") { backgroundPosition = RelativePosition("-336px -72px") }
        rule(".icon-fast-forward") { backgroundPosition = RelativePosition("-360px -72px") }
        rule(".icon-step-forward") { backgroundPosition = RelativePosition("-384px -72px") }
        rule(".icon-eject") { backgroundPosition = RelativePosition("-408px -72px") }
        rule(".icon-chevron-left") { backgroundPosition = RelativePosition("-432px -72px") }
        rule(".icon-chevron-right") { backgroundPosition = RelativePosition("-456px -72px") }

        rule(".icon-plus-sign") { backgroundPosition = RelativePosition("0px -96px") }
        rule(".icon-minus-sign") { backgroundPosition = RelativePosition("-24px -96px") }
        rule(".icon-remove-sign") { backgroundPosition = RelativePosition("-48px -96px") }
        rule(".icon-ok-sign") { backgroundPosition = RelativePosition("-72px -96px") }
        rule(".icon-question-sign") { backgroundPosition = RelativePosition("-96px -96px") }
        rule(".icon-info-sign") { backgroundPosition = RelativePosition("-120px -96px") }
        rule(".icon-screenshot") { backgroundPosition = RelativePosition("-144px -96px") }
        rule(".icon-remove-circle") { backgroundPosition = RelativePosition("-168px -96px") }
        rule(".icon-ok-circle") { backgroundPosition = RelativePosition("-192px -96px") }
        rule(".icon-ban-circle") { backgroundPosition = RelativePosition("-216px -96px") }
        rule(".icon-arrow-left") { backgroundPosition = RelativePosition("-240px -96px") }
        rule(".icon-arrow-right") { backgroundPosition = RelativePosition("-264px -96px") }
        rule(".icon-arrow-up") { backgroundPosition = RelativePosition("-289px -96px") } // 1px off
        rule(".icon-arrow-down") { backgroundPosition = RelativePosition("-312px -96px") }
        rule(".icon-share-alt") { backgroundPosition = RelativePosition("-336px -96px") }
        rule(".icon-resize-full") { backgroundPosition = RelativePosition("-360px -96px") }
        rule(".icon-resize-small") { backgroundPosition = RelativePosition("-384px -96px") }
        rule(".icon-plus") { backgroundPosition = RelativePosition("-408px -96px") }
        rule(".icon-minus") { backgroundPosition = RelativePosition("-433px -96px") }
        rule(".icon-asterisk") { backgroundPosition = RelativePosition("-456px -96px") }

        rule(".icon-exclamation-sign") { backgroundPosition = RelativePosition("0px -120px") }
        rule(".icon-gift") { backgroundPosition = RelativePosition("-24px -120px") }
        rule(".icon-leaf") { backgroundPosition = RelativePosition("-48px -120px") }
        rule(".icon-fire") { backgroundPosition = RelativePosition("-72px -120px") }
        rule(".icon-eye-open") { backgroundPosition = RelativePosition("-96px -120px") }
        rule(".icon-eye-close") { backgroundPosition = RelativePosition("-120px -120px") }
        rule(".icon-warning-sign") { backgroundPosition = RelativePosition("-144px -120px") }
        rule(".icon-plane") { backgroundPosition = RelativePosition("-168px -120px") }
        rule(".icon-calendar") { backgroundPosition = RelativePosition("-192px -120px") }
        rule(".icon-random") { backgroundPosition = RelativePosition("-216px -120px"); width = 16.px }
        rule(".icon-comment") { backgroundPosition = RelativePosition("-240px -120px") }
        rule(".icon-magnet") { backgroundPosition = RelativePosition("-264px -120px") }
        rule(".icon-chevron-up") { backgroundPosition = RelativePosition("-288px -120px") }
        rule(".icon-chevron-down") { backgroundPosition = RelativePosition("-313px -119px") } // 1px, 1px off
        rule(".icon-retweet") { backgroundPosition = RelativePosition("-336px -120px") }
        rule(".icon-shopping-cart") { backgroundPosition = RelativePosition("-360px -120px") }
        rule(".icon-folder-close") { backgroundPosition = RelativePosition("-384px -120px"); width = 16.px }
        rule(".icon-folder-open") { backgroundPosition = RelativePosition("-408px -120px"); width = 16.px }
        rule(".icon-resize-vertical") { backgroundPosition = RelativePosition("-432px -119px") } // 1px, 1px off
        rule(".icon-resize-horizontal") { backgroundPosition = RelativePosition("-456px -118px") } // 1px, 2px off

        rule(".icon-hdd") { backgroundPosition = RelativePosition("0px -144px") }
        rule(".icon-bullhorn") { backgroundPosition = RelativePosition("-24px -144px") }
        rule(".icon-bell") { backgroundPosition = RelativePosition("-48px -144px") }
        rule(".icon-certificate") { backgroundPosition = RelativePosition("-72px -144px") }
        rule(".icon-thumbs-up") { backgroundPosition = RelativePosition("-96px -144px") }
        rule(".icon-thumbs-down") { backgroundPosition = RelativePosition("-120px -144px") }
        rule(".icon-hand-right") { backgroundPosition = RelativePosition("-144px -144px") }
        rule(".icon-hand-left") { backgroundPosition = RelativePosition("-168px -144px") }
        rule(".icon-hand-up") { backgroundPosition = RelativePosition("-192px -144px") }
        rule(".icon-hand-down") { backgroundPosition = RelativePosition("-216px -144px") }
        rule(".icon-circle-arrow-right") { backgroundPosition = RelativePosition("-240px -144px") }
        rule(".icon-circle-arrow-left") { backgroundPosition = RelativePosition("-264px -144px") }
        rule(".icon-circle-arrow-up") { backgroundPosition = RelativePosition("-288px -144px") }
        rule(".icon-circle-arrow-down") { backgroundPosition = RelativePosition("-312px -144px") }
        rule(".icon-globe") { backgroundPosition = RelativePosition("-336px -144px") }
        rule(".icon-wrench") { backgroundPosition = RelativePosition("-360px -144px") }
        rule(".icon-tasks") { backgroundPosition = RelativePosition("-384px -144px") }
        rule(".icon-filter") { backgroundPosition = RelativePosition("-408px -144px") }
        rule(".icon-briefcase") { backgroundPosition = RelativePosition("-432px -144px") }
        rule(".icon-fullscreen") { backgroundPosition = RelativePosition("-456px -144px") }
    }


    override fun CssBuilder.tables() {
        // BASE TABLES
        rule("table") {
            maxWidth = 100.pct
            backgroundColor = vars.tableBackground
            borderCollapse = BorderCollapse.collapse
            borderSpacing = 0.px
        }

        // BASELINE STYLES
        rule(".table") {
            width = 100.pct
            marginBottom = vars.baseLineHeight
            // Cells
            ruleOf("th", "td") {
                padding = Padding(8.px)
                lineHeight = vars.baseLineHeight.lh
                textAlign = TextAlign.left
                verticalAlign = VerticalAlign.top
                borderTop = Border(1.px, BorderStyle.solid, vars.tableBorder)
            }
            th {
                fontWeight = FontWeight.bold
            }
            // Bottom align for column headings
            "thead th" {
                verticalAlign = VerticalAlign.bottom
            }
            // Remove top border from thead by default
            ruleOf(
                "caption + thead tr:first-child th",
                "caption + thead tr:first-child td",
                "colgroup + thead tr:first-child th",
                "colgroup + thead tr:first-child td",
                "thead:first-child tr:first-child th",
                "thead:first-child tr:first-child td"
            ) {
                borderTopWidth = 0.px
            }
            // Account for multiple tbody instances
            "tbody + tbody" {
                borderTop = Border(2.px, BorderStyle.solid, vars.tableBorder)
            }

            // Nesting
            ".table" {
                backgroundColor = vars.bodyBackground
            }
        }


        // CONDENSED TABLE W/ HALF PADDING
        rule(".table-condensed") {
            ruleOf("th", "td") {
                padding = Padding(4.px, 5.px)
            }
        }


        // BORDERED VERSION
        rule(".table-bordered") {
            border = Border(1.px, BorderStyle.solid, vars.tableBorder)
            borderCollapse = BorderCollapse.separate
            // Done so we can round those corners!
            declarations["*border-collapse"] = "collapse"
            // IE7 can't round corners anyway
            borderLeftWidth = 0.px
            with(mixins) { borderRadius(vars.baseBorderRadius) }
            ruleOf("th", "td") {
                borderLeft = Border(1.px, BorderStyle.solid, vars.tableBorder)
            }
            // Prevent a double border
            ruleOf(
                "caption + thead tr:first-child th",
                "caption + tbody tr:first-child th",
                "caption + tbody tr:first-child td",
                "colgroup + thead tr:first-child th",
                "colgroup + tbody tr:first-child th",
                "colgroup + tbody tr:first-child td",
                "thead:first-child tr:first-child th",
                "tbody:first-child tr:first-child th",
                "tbody:first-child tr:first-child td"
            ) {
                borderTopWidth = 0.px
            }
            // For first th/td in the first row in the first thead or tbody
            ruleOf(
                "thead:first-child tr:first-child > th:first-child",
                "tbody:first-child tr:first-child > td:first-child",
                "tbody:first-child tr:first-child > th:first-child"
            ) {
                with(mixins) { borderTopLeftRadius(vars.baseBorderRadius) }
            }
            // For last th/td in the first row in the first thead or tbody
            ruleOf(
                "thead:first-child tr:first-child > th:last-child",
                "tbody:first-child tr:first-child > td:last-child",
                "tbody:first-child tr:first-child > th:last-child"
            ) {
                with(mixins) { borderTopRightRadius(vars.baseBorderRadius) }
            }
            // For first th/td (can be either) in the last row in the last thead, tbody, and tfoot
            ruleOf(
                "thead:last-child tr:last-child > th:first-child",
                "tbody:last-child tr:last-child > td:first-child",
                "tbody:last-child tr:last-child > th:first-child",
                "tfoot:last-child tr:last-child > td:first-child",
                "tfoot:last-child tr:last-child > th:first-child"
            ) {
                with(mixins) { borderBottomLeftRadius(vars.baseBorderRadius) }
            }
            // For last th/td (can be either) in the last row in the last thead, tbody, and tfoot
            ruleOf(
                "thead:last-child tr:last-child > th:last-child",
                "tbody:last-child tr:last-child > td:last-child",
                "tbody:last-child tr:last-child > th:last-child",
                "tfoot:last-child tr:last-child > td:last-child",
                "tfoot:last-child tr:last-child > th:last-child"
            ) {
                with(mixins) { borderBottomRightRadius(vars.baseBorderRadius) }
            }

            // Clear border-radius for first and last td in the last row in the last tbody for table with tfoot
            "tfoot + tbody:last-child tr:last-child td:first-child" {
                with(mixins) { borderBottomLeftRadius(0.px) }
            }
            "tfoot + tbody:last-child tr:last-child td:last-child" {
                with(mixins) { borderBottomRightRadius(0.px) }
            }

            // Special fixes to round the left border on the first td/th
            ruleOf(
                "caption + thead tr:first-child th:first-child",
                "caption + tbody tr:first-child td:first-child",
                "colgroup + thead tr:first-child th:first-child",
                "colgroup + tbody tr:first-child td:first-child"
            ) {
                with(mixins) { borderTopLeftRadius(vars.baseBorderRadius) }
            }
            ruleOf(
                "caption + thead tr:first-child th:last-child",
                "caption + tbody tr:first-child td:last-child",
                "colgroup + thead tr:first-child th:last-child",
                "colgroup + tbody tr:first-child td:last-child"
            ) {
                with(mixins) { borderTopRightRadius(vars.baseBorderRadius) }
            }

        }


        // ZEBRA-STRIPING

        // Default zebra-stripe styles (alternating gray and transparent backgrounds)
        rule(".table-striped") {
            tbody {
                child("tr:nth-child(odd) > td > tr:nth-child(odd) > th") {
                    backgroundColor = vars.tableBackgroundAccent
                }
            }
        }


        // HOVER EFFECT
        // Placed here since it has to come after the potential zebra striping
        rule(".table-hover") {
            tbody {
                "tr:hover > td tr:hover > th" {
                    backgroundColor = vars.tableBackgroundHover
                }
            }
        }


        // TABLE CELL SIZING

        // Reset default grid behavior
        rule("table td[class*=\"span\"] table th[class*=\"span\"] .row-fluid table td[class*=\"span\"] .row-fluid table th[class*=\"span\"]") {
            display = Display.tableCell
            float = Float.none
            // undo default grid column styles
            marginLeft = 0.px // undo default grid column styles
        }

        // Change the column widths to account for td/th padding
        rule(".table td .table th") {
            with(mixins) {
                "&.span1" { tableColumns(1) }
                "&.span2" { tableColumns(2) }
                "&.span3" { tableColumns(3) }
                "&.span4" { tableColumns(4) }
                "&.span5" { tableColumns(5) }
                "&.span6" { tableColumns(6) }
                "&.span7" { tableColumns(7) }
                "&.span8" { tableColumns(8) }
                "&.span9" { tableColumns(9) }
                "&.span10" { tableColumns(10) }
                "&.span11" { tableColumns(11) }
                "&.span12" { tableColumns(12) }
            }
        }


        // TABLE BACKGROUNDS
        // Exact selectors below required to override .table-striped
        rule(".table tbody tr") {
            "&.success > td" {
                backgroundColor = vars.successBackground
            }
            "&.error > td" {
                backgroundColor = vars.errorBackground
            }
            "&.warning > td" {
                backgroundColor = vars.warningBackground
            }
            "&.info > td" {
                backgroundColor = vars.infoBackground
            }
        }

        // Hover states for .table-hover
        rule(".table-hover tbody tr") {
            "&.success:hover > td" {
                backgroundColor = vars.successBackground.darken(5)
            }
            "&.error:hover > td" {
                backgroundColor = vars.errorBackground.darken(5)
            }
            "&.warning:hover > td" {
                backgroundColor = vars.warningBackground.darken(5)
            }
            "&.info:hover > td" {
                backgroundColor = vars.infoBackground.darken(5)
            }
        }
    }


    override fun CssBuilder.thumbnails() {
        // Note: `.thumbnails` and `.thumbnails > li` are overriden in responsive files

        // Make wrapper ul behave like the grid
        rule(".thumbnails") {
            marginLeft = -vars.gridGutterWidth
            listStyleType = ListStyleType.none
            with(mixins) { clearfix() }
        }
        // Fluid rows have no left margin
        rule(".row-fluid .thumbnails") {
            marginLeft = 0.px
        }

        // Float li to make thumbnails appear in a row
        rule(".thumbnails > li") {
            float = Float.left
            // Explicity set the float since we don't require .span* classes
            marginBottom = vars.baseLineHeight
            marginLeft = vars.gridGutterWidth
        }

        // The actual thumbnail (can be `a` or `div`)
        rule(".thumbnail") {
            display = Display.block
            padding = Padding(4.px)
            lineHeight = vars.baseLineHeight.lh
            border = Border(1.px, BorderStyle.solid, Color("#ddd"))
            with(mixins) { borderRadius(vars.baseBorderRadius) }
            with(mixins) { boxShadow(0.px, 1.px, 3.px, rgb(0, 0, 0, .055)) }
            with(mixins) { transition("all .2s ease-in-out") }
        }
        // Add a hover/focus state for linked versions only
        ruleOf("a.thumbnail:hover", "a.thumbnail:focus") {
            borderColor = vars.linkColor
            with(mixins) { boxShadow(0.px, 1.px, 4.px, rgb(0, 105, 214, .25)) }
        }

        // Images and captions
        rule(".thumbnail > img") {
            display = Display.block
            maxWidth = 100.pct
            marginLeft = LinearDimension.auto
            marginRight = LinearDimension.auto
        }

        rule(".thumbnail .caption") {
            padding = Padding(9.px)
            color = vars.gray
        }
    }


    override fun CssBuilder.tooltip() {
        // Base class
        rule(".tooltip") {
            position = Position.absolute
            zIndex = vars.zindexTooltip
            display = Display.block
            visibility = Visibility.visible
            fontSize = 11.px
            lineHeight = 1.4.px.lh
            with(mixins) { opacity(0) }
            "&.in" { with(mixins) { opacity(80.0) } }
            "&.top" {
                marginTop = -3.px
                padding = Padding(5.px, 0.px)
            }
            "&.right" {
                marginLeft = 3.px
                padding = Padding(0.px, 5.px)
            }
            "&.bottom" {
                marginTop = 3.px
                padding = Padding(5.px, 0.px)
            }
            "&.left" {
                marginLeft = -3.px
                padding = Padding(0.px, 5.px)
            }
        }

        // Wrapper for the tooltip content
        rule(".tooltip-inner") {
            maxWidth = 200.px
            padding = Padding(8.px)
            color = vars.tooltipColor
            textAlign = TextAlign.center
            textDecoration = TextDecoration.none
            backgroundColor = vars.tooltipBackground
            with(mixins) { borderRadius(vars.baseBorderRadius) }
        }

        // Arrows
        rule(".tooltip-arrow") {
            position = Position.absolute
            width = 0.px
            height = 0.px
            borderColor = Color.transparent
            borderStyle = BorderStyle.solid
        }

        rule(".tooltip") {
            "&.top .tooltip-arrow" {
                bottom = 0.px
                left = 50.pct
                marginLeft = -vars.tooltipArrowWidth
                borderWidth = LinearDimension("${vars.tooltipArrowWidth} ${vars.tooltipArrowWidth} 0px")
                borderTopColor = vars.tooltipArrowColor
            }
            "&.right .tooltip-arrow" {
                top = 50.pct
                left = 0.px
                marginTop = -vars.tooltipArrowWidth
                borderWidth =
                    LinearDimension("${vars.tooltipArrowWidth} ${vars.tooltipArrowWidth} ${vars.tooltipArrowWidth} 0px")
                borderRightColor = vars.tooltipArrowColor
            }
            "&.left .tooltip-arrow" {
                top = 50.pct
                right = 0.px
                marginTop = -vars.tooltipArrowWidth
                borderWidth =
                    LinearDimension("${vars.tooltipArrowWidth} 0px ${vars.tooltipArrowWidth} ${vars.tooltipArrowWidth}")
                borderLeftColor = vars.tooltipArrowColor
            }
            "&.bottom .tooltip-arrow" {
                top = 0.px
                left = 50.pct
                marginLeft = -vars.tooltipArrowWidth
                borderWidth = LinearDimension(" 0px ${vars.tooltipArrowWidth} ${vars.tooltipArrowWidth}")
                borderBottomColor = vars.tooltipArrowColor
            }
        }
    }


    override fun CssBuilder.type() {
        // Body text
        rule("p") {
            margin = Margin(0.px, 0.px, vars.baseLineHeight / 2)
        }

        rule(".lead") {
            marginBottom = vars.baseLineHeight
            fontSize = vars.baseFontSize * 1.5
            fontWeight = FontWeight.w200
            lineHeight = (vars.baseLineHeight * 1.5).lh
        }


        // Emphasis & misc

        // Ex: 14px base font * 85% = about 12px
        rule("small") { fontSize = 85.pct }

        rule("strong") { fontWeight = FontWeight.bold }

        rule("em") { fontStyle = FontStyle.italic }

        rule("cite") { fontStyle = FontStyle.normal }

        // Utility classes
        rule(".muted") { color = vars.grayLight }
        ruleOf("a.muted:hover", "a.muted:focus") { color = vars.grayLight.darken(10) }

        rule(".text-warning") { color = vars.warningText }
        ruleOf("a.text-warning:hover", "a.text-warning:focus") { color = vars.warningText.darken(10) }

        rule(".text-error") { color = vars.errorText }
        ruleOf("a.text-error:hover", "a.text-error:focus") { color = vars.errorText.darken(10) }

        rule(".text-info") { color = vars.infoText }
        ruleOf("a.text-info:hover", "a.text-info:focus") { color = vars.infoText.darken(10) }

        rule(".text-success") { color = vars.successText }
        ruleOf("a.text-success:hover", "a.text-success:focus") { color = vars.successText.darken(10) }

        rule(".text-left") { textAlign = TextAlign.left }

        rule(".text-right") { textAlign = TextAlign.right }

        rule(".text-center") { textAlign = TextAlign.center }


        // Headings
        ruleOf("h1", "h2", "h3", "h4", "h5", "h6") {
            margin = Margin((vars.baseLineHeight / 2), 0.px)
            fontFamily = vars.headingsFontFamily
            fontWeight = vars.headingsFontWeight
            lineHeight = vars.baseLineHeight.lh
            color = vars.headingsColor
            declarations["textRendering"] = "optimizelegibility"
            // Fix the character spacing for headings
            small {
                fontWeight = FontWeight.normal
                lineHeight = 1.px.lh
                color = vars.grayLight
            }
        }

        ruleOf("h1", "h2", "h3") { lineHeight = (vars.baseLineHeight * 2).lh }

        rule("h1") { fontSize = vars.baseFontSize * 2.75 } // ~38px
        rule("h2") { fontSize = vars.baseFontSize * 2.25 } // ~32px
        rule("h3") { fontSize = vars.baseFontSize * 1.75 } // ~24px
        rule("h4") { fontSize = vars.baseFontSize * 1.25 } // ~18px
        rule("h5") { fontSize = vars.baseFontSize }

        rule("h6") { fontSize = vars.baseFontSize * 0.85 } // ~12px
        rule("h1 small") { fontSize = vars.baseFontSize * 1.75 } // ~24px
        rule("h2 small") { fontSize = vars.baseFontSize * 1.25 } // ~18px
        rule("h3 small") { fontSize = vars.baseFontSize }

        rule("h4 small") { fontSize = vars.baseFontSize }


        // Page header
        rule(".page-header") {
            paddingBottom = (vars.baseLineHeight / 2) - 1.px
            margin = Margin(vars.baseLineHeight, 0.px, (vars.baseLineHeight * 1.5))
            borderBottom = Border(1.px, BorderStyle.solid, vars.grayLighter)
        }


        // Lists

        // Unordered and Ordered lists
        rule("ul, ol") {
            padding = Padding(0.px)
            margin = Margin(0.px, 0.px, vars.baseLineHeight / 2, 25.px)
        }

        ruleOf("ul ul", "ul ol", "ol ol", "ol ul") {
            marginBottom = 0.px
        }

        rule("li") {
            lineHeight = vars.baseLineHeight.lh
        }

        // Remove default list styles
        ruleOf("ul.unstyled", "ol.unstyled") {
            marginLeft = 0.px
            listStyleType = ListStyleType.none
        }

        // Single-line list items
        ruleOf("ul.inline", "ol.inline") {
            marginLeft = 0.px
            listStyleType = ListStyleType.none
            child("li") {
                display = Display.inlineBlock
                with(mixins) { ie7InlineBlock() }
                paddingLeft = 5.px
                paddingRight = 5.px
            }
        }

        // Description Lists
        rule("dl") {
            marginBottom = vars.baseLineHeight
        }

        ruleOf("dt", "dd") {
            lineHeight = vars.baseLineHeight.lh
        }

        rule("dt") {
            fontWeight = FontWeight.bold
        }

        rule("dd") {
            marginLeft = vars.baseLineHeight / 2
        }
        // Horizontal layout (like forms)
        rule(".dl-horizontal") {
            with(mixins) { clearfix() }
            // Ensure dl clears floats if empty dd elements present
            dt {
                float = Float.left
                width = vars.horizontalComponentOffset - 20.px
                clear = Clear.left
                textAlign = TextAlign.right
                with(mixins) { textOverflow() }
            }
            dd {
                marginLeft = vars.horizontalComponentOffset
            }
        }

        // MISC
        // ----

        // Horizontal rules
        rule("hr") {
            margin = Margin(vars.baseLineHeight, 0.px)
            borderWidth = 0.px
            borderTop = Border(1.px, BorderStyle.solid, vars.hrBorder)
            borderBottom = Border(1.px, BorderStyle.solid, vars.white)
        }

        ruleOf(
            "abbr[title]", // Abbreviations and acronyms
            // Added data-* attribute to help out our tooltip plugin, per https://github.com/twbs/bootstrap/issues/5257
            "abbr[data-original-title]"
        ) {
            cursor = Cursor.help
            borderBottom = Border(1.px, BorderStyle.dotted, vars.grayLight)
        }

        rule("abbr.initialism") {
            fontSize = 90.pct
            textTransform = TextTransform.uppercase
        }

        // Blockquotes
        rule("blockquote") {
            padding = Padding(0.px, 0.px, 0.px, 15.px)
            margin = Margin(0.px, 0.px, vars.baseLineHeight)
            borderLeft = Border(5.px, BorderStyle.solid, vars.grayLighter)
            p {
                marginBottom = 0.px
                fontSize = vars.baseFontSize * 1.25
                fontWeight = FontWeight.w300
                lineHeight = 1.25.px.lh
            }
            small {
                display = Display.block
                lineHeight = vars.baseLineHeight.lh
                color = vars.grayLight
                "&:before" {
                    content = QuotedString("\u2014 \u00A0")
                }
            }

            // Float right with text-align: right
            "&.pull-right" {
                float = Float.right
                paddingRight = 15.px
                paddingLeft = 0.px
                borderRight = Border(5.px, BorderStyle.solid, vars.grayLighter)
                borderLeftWidth = 0.px
                ruleOf("p", "small") {
                    textAlign = TextAlign.right
                }
                small {
                    "&:before" {
                        content = QuotedString("")
                    }
                    "&:after" {
                        content = QuotedString("\u00A0 \u2014")
                    }
                }
            }
        }

        // Quotes
        ruleOf("q:before", "q:after", "blockquote:before", "blockquote:after") {
            content = QuotedString("")
        }

        // Addresses
        rule("address") {
            display = Display.block
            marginBottom = vars.baseLineHeight
            fontStyle = FontStyle.normal
            lineHeight = vars.baseLineHeight.lh
        }
    }


    override fun CssBuilder.utilities() {
        // Quick floats
        rule(".pull-right") {
            float = Float.right
        }

        rule(".pull-left") {
            float = Float.left
        }

        // Toggling content
        rule(".hide") {
            display = Display.none
        }

        rule(".show") {
            display = Display.block
        }

        // Visibility
        rule(".invisible") {
            visibility = Visibility.hidden
        }

        // For Affix plugin
        rule(".affix") {
            position = Position.fixed
        }
    }


    override fun CssBuilder.variables(){/**/}


    override fun CssBuilder.wells() {
        // Base class
        rule(".well") {
            minHeight = 20.px
            padding = Padding(19.px)
            marginBottom = 20.px
            backgroundColor = vars.wellBackground
            border = Border(1.px, BorderStyle.solid, vars.wellBackground.darken(7))
            with(mixins) { borderRadius(vars.baseBorderRadius) }
            with(mixins) { boxShadowInset(0.px, 1.px, 1.px, rgb(0, 0, 0, .05)) }
            blockquote {
                borderColor = Color("#ddd")
                borderColor = rgb(0, 0, 0, .15)
            }
        }

        // Sizes
        rule(".well-large") {
            padding = Padding(24.px)
            with(mixins) { borderRadius(vars.borderRadiusLarge) }
        }

        rule(".well-small") {
            padding = Padding(9.px)
            with(mixins) { borderRadius(vars.borderRadiusSmall) }
        }
    }

}
