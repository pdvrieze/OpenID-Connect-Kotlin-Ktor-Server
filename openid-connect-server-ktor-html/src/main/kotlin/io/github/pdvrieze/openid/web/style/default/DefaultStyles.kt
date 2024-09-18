package io.github.pdvrieze.openid.web.style.default

import io.github.pdvrieze.openid.web.style.Mixins
import io.github.pdvrieze.openid.web.style.Styles
import kotlinx.css.*
import kotlinx.css.Float
import kotlinx.css.properties.BoxShadow
import kotlinx.css.properties.BoxShadowInset
import kotlinx.css.properties.lh


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
        override val textcolor = grayDark


        // Links
        override val linkColor = Color("08c")
        override val linkColorHover get() = linkColor.darken(15)


        // Typography
        override val sansFontFamily = "\"Helvetica Neue\", Helvetica, Arial, sans-serif"
        override val serifFontFamily = "Georgia, \"Times New Roman\", Times, serif"
        override val monoFontFamily = "Monaco, Menlo, Consolas, \"Courier New\", monospace";

        override val baseFontSize = 14.px
        override val baseFontFamily get() = sansFontFamily
        override val baseLineHeight = 20.px
        override val altFontFamily get() = serifFontFamily

        override val headingsFontFamily = "inherit";

        // empty to use BS default, vars.baseFontFamily
        override val headingsFontWeight = FontWeight.bold;

        // instead of browser default, bold
        override val headingsColor = Color.inherit
        // empty to use BS default, vars.textColor


// Component sizing
// Based on 14px font-size and 20px line-height

        override val fontSizeLarge get() = baseFontSize * 1.25;

        // ~18px
        override val fontSizeSmall get() = baseFontSize * 0.85;

        // ~12px
        override val fontSizeMini get() = baseFontSize * 0.75;
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
        override val tableBackground = Color.transparent;

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

        override val dropdownLinkcolor get() = grayDark
        override val dropdownLinkColorHover get() = white
        override val dropdownLinkColorActive get() = white

        override val dropdownLinkBackgroundActive get() = linkColor
        override val dropdownLinkBackgroundHover get() = dropdownLinkBackgroundActive


// COMPONENT vars.IABLES


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
        override val iconSpritePath = "../img/glyphicons-halflings.png";
        override val iconWhiteSpritePath = "../img/glyphicons-halflings-white.png";


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
        override val navbarCollapseDesktopWidth = navbarCollapseWidth + 1.px;

        override val navbarHeight = 40.px
        override val navbarBackgroundHighlight = Color("ffffff")
        override val navbarBackground = navbarBackgroundHighlight.darken(5)
        override val navbarBorder = navbarBackground.darken(12)

        override val navbarText = Color("777")
        override val navbarLinkColor = Color("777")
        override val navbarLinkColorHover get() = grayDark
        override val navbarLinkColorActive get() = gray
        override val navbarLinkBackgroundHover = Color.transparent
        override val navbarLinkBackgroundActive = navbarBackground.darken(5);

        override val navbarBrandcolor get() = navbarLinkColor

        // Inverted navbar
        override val navbarInverseBackground = Color("111111")
        override val navbarInverseBackgroundHighlight = Color("222222")
        override val navbarInverseBorder = Color("252525")

        override val navbarInverseText get() = grayLight
        override val navbarInverseLinkcolor get() = grayLight
        override val navbarInverseLinkColorHover get() = white
        override val navbarInverseLinkColorActive get() = navbarInverseLinkColorHover
        override val navbarInverseLinkBackgroundHover = Color.transparent;
        override val navbarInverseLinkBackgroundActive get() = navbarInverseBackground

        override val navbarInverseSearchBackground = navbarInverseBackground.lighten(25)
        override val navbarInverseSearchBackgroundFocus get() = white
        override val navbarInverseSearchBorder get() = navbarInverseBackground
        override val navbarInverseSearchPlaceholderColor = Color("ccc")

        override val navbarInverseBrandcolor get() = navbarInverseLinkcolor


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

        // darken(spin(vars.warningBackground, -10), 3%);
        override val warningBorder = hsl(24, 25, 252).darken(3)

        override val errorText = Color("b94a48")
        override val errorBackground = Color("f2dede")

        // darken(spin(vars.errorBackground, -10), 3%);
        override val errorBorder = hsl(230, 21, 242).darken(3)

        override val successText = Color("468847")
        override val successBackground = Color("dff0d8")

        // darken(spin(vars.successBackground, -10), 5%);
        override val successBorder = hsl(76, 25, 240).darken(5)

        override val infoText = Color("3a87ad")
        override val infoBackground = Color("d9edf7")

        // darken(spin(vars.infoBackground, -10), 7%);
        override val infoBorder = hsl(174, 31, 247).darken(7)


        // Tooltips and popovers
        override val tooltipColor = Color("fff")
        override val tooltipBackground = Color("000")
        override val tooltipArrowWidth = 5.px
        override val tooltipArrowcolor get() = tooltipBackground

        override val popoverBackground = Color("fff")
        override val popoverArrowWidth = 10.px
        override val popoverArrowColor = Color("fff")
        override val popoverTitleBackground = popoverBackground.darken(3)

        // Special enhancement for popovers
        override val popoverArrowOuterWidth = popoverArrowWidth + 1.px;
        override val popoverArrowOuterColor = rgb(0, 0, 0, .25)


// GRID


        // Default 940px grid
        override val gridColumns = 12;
        override val gridColumnWidth = 60.px
        override val gridGutterWidth = 20.px
        override val gridRowWidth = (gridColumnWidth * gridColumns) + (gridGutterWidth * (gridColumns-1));

        // 1200px min
        override val gridColumnWidth1200 = 70.px
        override val gridGutterWidth1200 = 30.px
        override val gridRowWidth1200 = (gridColumnWidth1200 * gridColumns) + (gridGutterWidth1200 * (gridColumns-1));

        // 768px-979px
        override val gridColumnWidth768 = 42.px
        override val gridGutterWidth768 = 20.px
        override val gridRowWidth768 = (gridColumnWidth768 * gridColumns) + (gridGutterWidth768 * (gridColumns-1));


        // Fluid grid
        override val fluidGridColumnWidth = percentage(gridColumnWidth, gridRowWidth)
        override val fluidGridGutterWidth = percentage(gridGutterWidth, gridRowWidth);

        // 1200px min
        override val fluidGridColumnWidth1200 = percentage(gridColumnWidth1200, gridRowWidth1200);
        override val fluidGridGutterWidth1200 = percentage(gridGutterWidth1200, gridRowWidth1200);

        // 768px-979px
        override val fluidGridColumnWidth768 = percentage(gridColumnWidth768, gridRowWidth768);
        override val fluidGridGutterWidth768 = percentage(gridGutterWidth768, gridRowWidth768);
    }
    
    override fun CssBuilder.accordion() {
        // Parent container
        rule(".accordion") {
            marginBottom = vars.baseLineHeight
        }

        // Group == heading + body
        rule(".accordion-group") {
            marginBottom = 2.px;
            border = Border(1.px, BorderStyle.solid, Color("#e5e5e5"))
            borderRadius = vars.baseBorderRadius
        }

        rule(".accordion-heading") {
            borderBottomWidth = 0.px;
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
            declarations["text-shadow"] = "0px 1px 0px rgba(255, 255, 255, .5)";
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

        rule(".alert-danger .alert-error") {
            backgroundColor = vars.errorBackground
            borderColor =  vars.errorBorder
            color = vars.errorText
        }

        rule(".alert-danger h4 .alert-error h4") {
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

        rule(".alert-block > p .alert-block > ul") {
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

        rule(".btn-group > .btn .btn-group > .dropdown-menu .btn-group > .popover") {
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
        rule(".btn-group > .btn:last-child .btn-group > .dropdown-toggle") {
            with(mixins) { borderTopRightRadius(vars.baseBorderRadius) }
            with(mixins) { borderBottomRightRadius(vars.baseBorderRadius) }
        }
        // Reset corners for large buttons
        rule(".btn-group > .btn.large:first-child") {
            marginLeft = 0.px
            with(mixins) { borderTopLeftRadius(vars.borderRadiusLarge) }
            with(mixins) { borderBottomLeftRadius(vars.borderRadiusLarge) }
        }

        rule(".btn-group > .btn.large:last-child .btn-group > .large.dropdown-toggle") {
            with(mixins) { borderTopRightRadius(vars.borderRadiusLarge) }
            with(mixins) { borderBottomRightRadius(vars.borderRadiusLarge) }
        }

        // On hover/focus/active, bring the proper btn to front
        rule(".btn-group > .btn:hover .btn-group > .btn:focus .btn-group > .btn:active .btn-group > .btn.active") {
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

        rule(".btn-mini .caret .btn-small .caret") {
            marginTop = 8.px
        }
        // Upside down carets for .dropup
        rule(".dropup .btn-large .caret") {
            borderBottomWidth = 5.px;
        }


        // Account for other colors
        rule(".btn-primary .btn-warning .btn-danger .btn-info .btn-success .btn-inverse") {
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
            maxWidth = 100.pct;
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


    override fun CssBuilder.buttons(){/*
// Base styles

// Core
rule(".btn") {
  display = Display.inlineBlock
  with(mixins) { ie7InlineBlock() }
  padding = Padding(4.px, 12.px)
  marginBottom = 0.px // For input.btn
  fontSize = vars.baseFontSize
  lineHeight = vars.baseLineHeight
  text-align: center;
  verticalAlign = VerticalAlign.middle
  cursor = Cursor.pointer
  with(mixins) { buttonBackground(vars.btnBackground, vars.btnBackgroundHighlight, vars.grayDark, 0px 1px 1px rgba(255,255,255,.75)) }
  border = Border(1.px, BorderStyle.solid, vars.btnBorder)
  declarations[*border] = "0px"
 // Remove the border to prevent IE7's black border on input:focus
  border-bottom-color: darken(vars.btnBorder, 10%);
  with(mixins) { borderRadius(vars.baseBorderRadius) }
  with(mixins) { ie7RestoreLeftWhitespace() }
 // Give IE7 some love
  with(mixins) { boxShadow(~"inset 0px 1px 0px rgba(255,255,255,.2), 0px 1px 2px rgba(0,0,0,.05)") }

  // Hover/focus state
  &:hover &:focus {
    color = vars.grayDark
    text-decoration: none;
    background-position: 0px -15px;

    // transition is only when going to hover/focus, otherwise the background
    // behind the gradient (there for IE<=9 fallback) gets mismatched
    with(mixins) { transition(background-position .1s linear) }
  }

  // Focus state for keyboard and accessibility
  &:focus {
    with(mixins) { tabFocus() }
  }

  // Active state
  &.active &:active {
    backgroundImage = Image.none
    outlineWidth = 0.px
    with(mixins) { boxShadow(~"inset 0px 2px 4px rgba(0,0,0,.15), 0px 1px 2px rgba(0,0,0,.05)") }
  }

  // Disabled state
  &.disabled &[disabled] {
    cursor = Cursor.default
    backgroundImage = Image.none
    with(mixins) { opacity(65) }
    with(mixins) { boxShadow(none) }
  }

}



// Button Sizes

// Large
rule(".btn-large") {
  padding: vars.paddingLarge;
  fontSize = vars.fontSizeLarge
  with(mixins) { borderRadius(vars.borderRadiusLarge) }
}

rule(".btn-large [class^="icon-"] .btn-large [class*=" icon-"]") {
  marginTop = 4.px
}

// Small
rule(".btn-small") {
  padding: vars.paddingSmall;
  fontSize = vars.fontSizeSmall
  with(mixins) { borderRadius(vars.borderRadiusSmall) }
}

rule(".btn-small [class^="icon-"] .btn-small [class*=" icon-"]") {
  marginTop = 0.px
}

rule(".btn-mini [class^="icon-"] .btn-mini [class*=" icon-"]") {
  marginTop = -1.px
}

// Mini
rule(".btn-mini") {
  padding: vars.paddingMini;
  fontSize = vars.fontSizeMini
  with(mixins) { borderRadius(vars.borderRadiusSmall) }
}


// Block button
rule(".btn-block") {
  display = Display.block
  width: 100%;
  paddingLeft = 0.px
  paddingRight = 0.px
  with(mixins) { boxSizing(border-box) }
}

// Vertically space out multiple block buttons
rule(".btn-block + .btn-block") {
  marginTop = 5.px
}

// Specificity overrides
rule("input[type="submit"] input[type="reset"] input[type="button"]") {
  &.btn-block {
    width: 100%;
  }
}



// Alternate buttons

// Provide *some* extra contrast for those who can get it
rule(".btn-primary.active .btn-warning.active .btn-danger.active .btn-success.active .btn-info.active .btn-inverse.active") {
  color: rgba(255,255,255,.75);
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
rule("button.btn input[type="submit"].btn") {

  // Firefox 3.6 only I believe
  &::-moz-focus-inner {
    padding = Padding(0.px)
    border: 0px;
  }

  // IE7 has some default padding on button controls
  declarations["*paddingTop"] = 3.px
  declarations["*paddingBottom"] = 3.px
rule("  &.btn-large") {
    declarations["*paddingTop"] = 7.px
    declarations["*paddingBottom"] = 7.px
  }
  &.btn-small {
    declarations["*paddingTop"] = 3.px
    declarations["*paddingBottom"] = 3.px
  }
  &.btn-mini {
    declarations["*paddingTop"] = 1.px
    declarations["*paddingBottom"] = 1.px
  }
}


// Link buttons

// Make a button look and behave like a link
rule(".btn-link .btn-link:active .btn-link[disabled]") {
  background-color: transparent;
  backgroundImage = Image.none
  with(mixins) { boxShadow(none) }
}

rule(".btn-link") {
  border-color: transparent;
  cursor = Cursor.pointer
  color = vars.linkColor
  with(mixins) { borderRadius(0px) }
}

rule(".btn-link:hover .btn-link:focus") {
  color = vars.linkColorHover
  text-decoration: underline;
  background-color: transparent;
}

rule(".btn-link[disabled]:hover .btn-link[disabled]:focus") {
  color = vars.grayDark
  text-decoration: none;
}
    */}


    override fun CssBuilder.carousel(){/*
rule(".carousel") {
  position = Position.relative
  marginBottom = vars.baseLineHeight
  lineHeight = 1.px
}

rule(".carousel-inner") {
  overflow: hidden;
  width: 100%;
  position = Position.relative
}

rule(".carousel-inner") {
rule("  > .item") {
    display = Display.none
    position = Position.relative
    with(mixins) { transition(.6s ease-in-out left) }

    // Account for jankitude on images
    child("img > a > img") {
      display = Display.block
      lineHeight = 1.px
    }
  }

rule("  > .active > .next > .prev") { display = Display.block }

rule("  > .active") {
    left = 0.px
  }

rule("  > .next > .prev") {
    position = Position.absolute
    top = 0.px
    width: 100%;
  }

rule("  > .next") {
    left: 100%;
  }
  child(".prev") {
    left: -100%;
  }
  child(".next.left > .prev.right") {
    left = 0.px
  }

rule("  > .active.left") {
    left: -100%;
  }
  child(".active.right") {
    left: 100%;
  }

}

// Left/right controls for nav
rule(".carousel-control") {
  position = Position.absolute
  top: 40%;
  left = 15.px
  width: 40px;
  height: 40px;
  marginTop = -20.px
  fontSize = 60.px
  font-weight: 100;
  line-height: 30px;
  color = vars.white
  text-align: center;
  background: vars.grayDarker;
  border = Border(3.px, BorderStyle.solid, vars.white)
  with(mixins) { borderRadius(23px) }
  with(mixins) { opacity(50) }

  // we can't have this transition here
  // because webkit cancels the carousel
  // animation if you trip this while
  // in the middle of another animation
  // ;
_;
  // .transition(opacity .2s linear);

  // Reposition the right one
  &.right {
    left: auto;
    right = 15.px
  }

  // Hover/focus state
  &:hover &:focus {
    color = vars.white
    text-decoration: none;
    with(mixins) { opacity(90) }
  }
}

// Carousel indicator pips
rule(".carousel-indicators") {
  position = Position.absolute
  top = 15.px
  right = 15.px
  zIndex = 5
  margin = Margin(0.px)
  list-style: none;
rule("  li") {
    display = Display.block
    float: left;
    width: 10px;
    height: 10px;
    marginLeft = 5.px
    text-indent: -999px;
    backgroundColor = Color("#ccc")
    background-color: rgba(255,255,255,.25);
    border-radius: 5px;
  }
  .active {
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
  background: vars.grayDark;
  background: rgba(0,0,0,.75);
}

rule(".carousel-caption h4 .carousel-caption p") {
  color = vars.white
  lineHeight = vars.baseLineHeight
}

rule(".carousel-caption h4") {
  margin = Margin(0.px, 0.px, 5.px)
}

rule(".carousel-caption p") {
  marginBottom = 0.px
}
    */}


    override fun CssBuilder.close(){/*
rule(".close") {
  float: right;
  fontSize = 20.px
  font-weight: bold;
  lineHeight = vars.baseLineHeight
  color = vars.black
  text-shadow: 0px 1px 0px rgba(255,255,255,1);
  with(mixins) { opacity(20) }
  &:hover &:focus {
    color = vars.black
    text-decoration: none;
    cursor = Cursor.pointer
    with(mixins) { opacity(40) }
  }
}

// Additional properties for button version
// iOS requires the button element instead of an anchor tag.
// If you want the anchor version, it requires `href="#"`.
rule("button.close") {
  padding = Padding(0.px)
  cursor = Cursor.pointer
  background: transparent;
  border: 0px;
  -webkit-appearance: none;
}
    */}


    override fun CssBuilder.code(){/*
// Inline and block code styles
rule("code pre") {
  padding = Padding(0.px, 3.px, 2.px)
  #font > #family > .monospace;
  fontSize = vars.baseFontSize-2
  color = vars.grayDark
  with(mixins) { borderRadius(3px) }
}

// Inline code
rule("code") {
  padding = Padding(2.px, 4.px)
  color: #d14;
  backgroundColor = Color("#f7f7f9")
  border = Border(1.px, BorderStyle.solid, Color(#e1e1e8))
  whiteSpace = WhiteSpace.nowrap
}

// Blocks of code
rule("pre") {
  display = Display.block
  padding: (vars.baseLineHeight-1) / 2;
  margin: 0px 0px vars.baseLineHeight / 2;
  fontSize = vars.baseFontSize-1
 // 14px to 13px
  lineHeight = vars.baseLineHeight
  word-break: break-all;
  word-wrap: break-word;
  whiteSpace = WhiteSpace.pre
  white-space: pre-wrap;
  backgroundColor = Color("#f5f5f5")
  border = Border(1.px, BorderStyle.solid, Color(#ccc))
 // fallback for IE7-8
  border: 1px solid rgba(0,0,0,.15);
  with(mixins) { borderRadius(vars.baseBorderRadius) }

  // Make prettyprint styles more spaced out for readability
  &.prettyprint {
    marginBottom = vars.baseLineHeight
  }

  // Account for some code outputs that place code tags in pre tags
  code {
    padding = Padding(0.px)
    color = Color.inherit
    whiteSpace = WhiteSpace.pre
    white-space: pre-wrap;
    background-color: transparent;
    border: 0px;
  }
}

// Enable scrollable blocks of code
rule(".pre-scrollable") {
  max-height: 340px;
  overflow-y: scroll;
}
    */}


    override fun CssBuilder.componentAnimations(){/*
rule(".fade") {
  opacity: 0px;
  with(mixins) { transition(opacity .15s linear) }
  &.in {
    opacity: 1;
  }
}

rule(".collapse") {
  position = Position.relative
  height: 0px;
  overflow: hidden;
  with(mixins) { transition(height .35s ease) }
  &.in {
    height: auto;
  }
}
    */}


    override fun CssBuilder.dropdowns(){/*
// Use the .menu class on any <li> element within the topbar or ul.tabs and you'll get some superfancy dropdowns
rule(".dropup .dropdown") {
  position = Position.relative
}

rule(".dropdown-toggle") {
  // The caret makes the toggle a bit too tall in IE7
  declarations["*marginBottom"] = -3.px
}

rule(".dropdown-toggle:active .open .dropdown-toggle") {
  outlineWidth = 0.px
}

// Dropdown arrow/caret
rule(".caret") {
  display = Display.inlineBlock
  width: 0px;
  height: 0px;
  verticalAlign = VerticalAlign.top
  border-top:   4px solid vars.black;
  borderRight = Border(4.px, BorderStyle.solid, Color(solid))
  border-left:  4px solid transparent;
  content: "";
}

// Place the caret
rule(".dropdown .caret") {
  marginTop = 8.px
  marginLeft = 2.px
}

// The dropdown menu (ul)
rule(".dropdown-menu") {
  position = Position.absolute
  top: 100%;
  left = 0.px
  z-index: vars.zindexDropdown;
  display = Display.none // none by default, but block on "open" of the menu
  float: left;
  min-width: 160px;
  padding = Padding(5.px, 0.px)
  margin = Margin(2.px, 0.px, 0.px)
 // override default ul
  list-style: none;
  backgroundColor = vars.dropdownBackground
  border = Border(1.px, BorderStyle.solid, Color(#ccc))
 // Fallback for IE7-8
  border = Border(1.px, BorderStyle.solid, vars.dropdownBorder)
  declarations[*border-right-width] = "2px"
  declarations[*border-bottom-width] = "2px"
  with(mixins) { borderRadius(6px) }
  with(mixins) { boxShadow(0px 5px 10px rgba(0,0,0,.2)) }
  -webkit-background-clip: padding-box;
     -moz-background-clip: padding;
          background-clip: padding-box;

  // Aligns the dropdown menu to right
  &.pull-right {
    right = 0.px
    left: auto;
  }

  // Dividers (basically an hr) within the dropdown
  .divider {
    with(mixins) { navDivider(vars.dropdownDividerTop, vars.dropdownDividerBottom) }
  }

  // Links within the dropdown menu
  child("li > a") {
    display = Display.block
    padding = Padding(3.px, 20.px)
    clear: both;
    font-weight: normal;
    lineHeight = vars.baseLineHeight
    color = vars.dropdownLinkColor
    whiteSpace = WhiteSpace.nowrap
  }
}

// Hover/Focus state
rule(".dropdown-menu > li > a:hover .dropdown-menu > li > a:focus .dropdown-submenu:hover > a .dropdown-submenu:focus > a") {
  text-decoration: none;
  color = vars.dropdownLinkColorHover
  #gradient > .vertical(vars.dropdownLinkBackgroundHover, darken(vars.dropdownLinkBackgroundHover, 5%));
}

// Active state
rule(".dropdown-menu > .active > a .dropdown-menu > .active > a:hover .dropdown-menu > .active > a:focus") {
  color = vars.dropdownLinkColorActive
  text-decoration: none;
  outlineWidth = 0.px
  #gradient > .vertical(vars.dropdownLinkBackgroundActive, darken(vars.dropdownLinkBackgroundActive, 5%));
}

// Disabled state
// Gray out text and ensure the hover/focus state remains gray
rule(".dropdown-menu > .disabled > a .dropdown-menu > .disabled > a:hover .dropdown-menu > .disabled > a:focus") {
  color = vars.grayLight
}
// Nuke hover/focus effects
rule(".dropdown-menu > .disabled > a:hover .dropdown-menu > .disabled > a:focus") {
  text-decoration: none;
  background-color: transparent;
  backgroundImage = Image.none
 // Remove CSS gradient
  with(mixins) { resetFilter() }
  cursor = Cursor.default
}

// Open state for the dropdown
rule(".open") {
  // IE7's z-index only goes to the nearest positioned ancestor, which would
  // make the menu appear below buttons that appeared later on the page
  declarations[*z-index] = "vars.zindexDropdown"
rule("  & > .dropdown-menu") {
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
  z-index: vars.zindexDropdown-10;
}

// Right aligned dropdowns
rule(".pull-right > .dropdown-menu") {
  right = 0.px
  left: auto;
}

// Allow for dropdowns to go bottom up (aka, dropup-menu)
// Just add .dropup after the standard .dropdown class and you're set, bro.
// TODO: abstract this so that the navbar fixed styles are not placed here?
rule(".dropup .navbar-fixed-bottom .dropdown") {
  // Reverse the caret
  .caret {
    borderTop = Border(0.px)
    borderBottom = Border(4.px, BorderStyle.solid, Color(solid))
    content: "";
  }
  // Different positioning for bottom up menu
  .dropdown-menu {
    top: auto;
    bottom: 100%;
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
  left: 100%;
  marginTop = -6.px
  marginLeft = -1.px
  with(mixins) { borderRadius(0px 6px 6px 6px) }
}

rule(".dropdown-submenu:hover > .dropdown-menu") {
  display = Display.block
}

// Dropups
rule(".dropup .dropdown-submenu > .dropdown-menu") {
  top: auto;
  bottom = 0.px
  marginTop = 0.px
  marginBottom = -2.px
  with(mixins) { borderRadius(5px 5px 5px 0px) }
}

// Caret to indicate there is a submenu
rule(".dropdown-submenu > a:after") {
  display = Display.block
  content: " ";
  float: right;
  width: 0px;
  height: 0px;
  border-color: transparent;
  border-style: solid;
  border-width: 5px 0px 5px 5px;
  border-left-color: darken(vars.dropdownBackground, 20%);
  marginTop = 5.px
  marginRight = -10.px
}

rule(".dropdown-submenu:hover > a:after") {
  border-left-color = vars.dropdownLinkColorHover
}

// Left aligned submenus
rule(".dropdown-submenu.pull-left") {
  // Undo the float
  // Yes, this is awkward since .pull-left adds a float, but it sticks to our conventions elsewhere.
  float: none;

  // Positioning the submenu
  child(".dropdown-menu") {
    left: -100%;
    marginLeft = 10.px
    with(mixins) { borderRadius(6px 0px 6px 6px) }
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
    */}


    override fun CssBuilder.forms(){/*
// GENERAL STYLES

// Make all forms have space below them
rule("form") {
  margin: 0px 0px vars.baseLineHeight;
}

rule("fieldset") {
  padding = Padding(0.px)
  margin = Margin(0.px)
  border: 0px;
}

// Groups of fields with labels on top (legends)
rule("legend") {
  display = Display.block
  width: 100%;
  padding = Padding(0.px)
  marginBottom = vars.baseLineHeight
  fontSize = vars.baseFontSize * 1.5
  line-height: vars.baseLineHeight * 2;
  color = vars.grayDark
  border: 0px;
  borderBottom = Border(1.px, BorderStyle.solid, Color(solid))

  // Small
  small {
    fontSize = vars.baseLineHeight * .75
    color = vars.grayLight
  }
}

// Set font for forms
rule("label input button select textarea") {
  #font > .shorthand(vars.baseFontSize,normal,vars.baseLineHeight);
 // Set size, weight, line-height here
}

rule("input button select textarea") {
  font-family: vars.baseFontFamily;
 // And only set font-family here for those that need it (note the missing label element)
}

// Identify controls by their labels
rule("label") {
  display = Display.block
  marginBottom = 5.px
}

// Form controls

// Shared size and type resets
rule("select textarea input[type="text"] input[type="password"] input[type="datetime"] input[type="datetime-local"] input[type="date"] input[type="month"] input[type="time"] input[type="week"] input[type="number"] input[type="email"] input[type="url"] input[type="search"] input[type="tel"] input[type="color"] .uneditable-input") {
  display = Display.inlineBlock
  height: vars.baseLineHeight;
  padding = Padding(4.px, 6.px)
  marginBottom = vars.baseLineHeight / 2
  fontSize = vars.baseFontSize
  lineHeight = vars.baseLineHeight
  color = vars.gray
  with(mixins) { borderRadius(vars.inputBorderRadius) }
  verticalAlign = VerticalAlign.middle
}

// Reset appearance properties for textual inputs and textarea
// Declare width for legacy (can't be on input[type=*] selectors or it's too specific)
rule("input textarea .uneditable-input") {
  width: 206px;
 // plus 12px padding and 2px border
}
// Reset height since textareas have rows
rule("textarea") {
  height: auto;
}
// Everything else
rule("textarea input[type="text"] input[type="password"] input[type="datetime"] input[type="datetime-local"] input[type="date"] input[type="month"] input[type="time"] input[type="week"] input[type="number"] input[type="email"] input[type="url"] input[type="search"] input[type="tel"] input[type="color"] .uneditable-input") {
  backgroundColor = vars.inputBackground
  border = Border(1.px, BorderStyle.solid, vars.inputBorder)
  with(mixins) { boxShadow(inset 0px 1px 1px rgba(0,0,0,.075)) }
  with(mixins) { transition(~"border linear .2s, box-shadow linear .2s") }

  // Focus state
  &:focus {
    border-color: rgba(82,168,236,.8);
    outlineWidth = 0.px
    outline: thin dotted \9;
 /* IE6-9 */
    with(mixins) { boxShadow(~"inset 0px 1px 1px rgba(0,0,0,.075), 0px 0px 8px rgba(82,168,236,.6)") }
  }
}

// Position radios and checkboxes better
rule("input[type="radio"] input[type="checkbox"]") {
  margin = Margin(4.px, 0.px, 0.px)
  declarations["*marginTop"] = 0.px /* IE7 */
  marginTop = 1px \9
 /* IE8-9 */
  line-height: normal;
}

// Reset width of input images, buttons, radios, checkboxes
rule("input[type="file"] input[type="image"] input[type="submit"] input[type="reset"] input[type="button"] input[type="radio"] input[type="checkbox"]") {
  width: auto;
 // Override of generic input selector
}

// Set the height of select and file controls to match text inputs
rule("select input[type="file"]") {
  height: vars.inputHeight;
 /* In IE7, the height of the select element cannot be changed by height, only font-size */
  declarations["*marginTop"] = 4.px /* For IE7, add top margin to align select with labels */
  lineHeight = vars.inputHeight
}

// Make select elements obey height by applying a border
rule("select") {
  width: 220px;
 // default input width + 10px of padding that doesn't get applied
  border = Border(1.px, BorderStyle.solid, vars.inputBorder)
  backgroundColor = vars.inputBackground
 // Chrome on Linux and Mobile Safari need background-color
}

// Make multiple select elements height not fixed
rule("select[multiple] select[size]") {
  height: auto;
}

// Focus for select, file, radio, and checkbox
rule("select:focus input[type="file"]:focus input[type="radio"]:focus input[type="checkbox"]:focus") {
  with(mixins) { tabFocus() }
}


// Uneditable inputs

// Make uneditable inputs look inactive
rule(".uneditable-input .uneditable-textarea") {
  color = vars.grayLight
  background-color: darken(vars.inputBackground, 1%);
  borderColor =  vars.inputBorder
  with(mixins) { boxShadow(inset 0px 1px 2px rgba(0,0,0,.025)) }
  cursor: not-allowed;
}

// For text that needs to appear as an input but should not be an input
rule(".uneditable-input") {
  overflow: hidden;
 // prevent text from wrapping, but still cut it off like an input does
  whiteSpace = WhiteSpace.nowrap
}

// Make uneditable textareas behave like a textarea
rule(".uneditable-textarea") {
  width: auto;
  height: auto;
}


// Placeholder

// Placeholder text gets special styles because when browsers invalidate entire lines if it doesn't understand a selector
rule("input textarea") {
  with(mixins) { placeholder() }
}


// CHECKBOXES & RADIOS

// Indent the labels to position radios/checkboxes as hanging
rule(".radio .checkbox") {
  min-height: vars.baseLineHeight;
 // clear the floating input if there is no label text
  paddingLeft = 20.px
}

rule(".radio input[type="radio"] .checkbox input[type="checkbox"]") {
  float: left;
  marginLeft = -20.px
}

// Move the options list down to align with labels
rule(".controls > .radio:first-child .controls > .checkbox:first-child") {
  paddingTop = 5.px // has to be padding because margin collaspes
}

// Radios and checkboxes on same line
// TODO v3: Convert .inline to .control-inline
rule(".radio.inline .checkbox.inline") {
  display = Display.inlineBlock
  paddingTop = 5.px
  marginBottom = 0.px
  verticalAlign = VerticalAlign.middle
}

rule(".radio.inline + .radio.inline .checkbox.inline + .checkbox.inline") {
  marginLeft = 10.px // space out consecutive inline controls
}



// INPUT SIZES

// General classes for quick sizes
rule(".input-mini") { width: 60px;
 }

rule(".input-small") { width: 90px;
 }

rule(".input-medium") { width: 150px;
 }

rule(".input-large") { width: 210px;
 }

rule(".input-xlarge") { width: 270px;
 }

rule(".input-xxlarge") { width: 530px;
 }

// Grid style input sizes
input[class*="span"] select[class*="span"] textarea[class*="span"] .uneditable-input[class*="span"] // Redeclare since the fluid row class is more specific
rule(".row-fluid input[class*="span"] .row-fluid select[class*="span"] .row-fluid textarea[class*="span"] .row-fluid .uneditable-input[class*="span"]") {
  float: none;
  marginLeft = 0.px
}
// Ensure input-prepend/append never wraps
rule(".input-append input[class*="span"] .input-append .uneditable-input[class*="span"] .input-prepend input[class*="span"] .input-prepend .uneditable-input[class*="span"] .row-fluid input[class*="span"] .row-fluid select[class*="span"] .row-fluid textarea[class*="span"] .row-fluid .uneditable-input[class*="span"] .row-fluid .input-prepend [class*="span"] .row-fluid .input-append [class*="span"]") {
  display = Display.inlineBlock
}



// GRID SIZING FOR INPUTS

// Grid sizes
#grid > .input(vars.gridColumnWidth, vars.gridGutterWidth);

// Control row for multiple inputs per line
rule(".controls-row") {
  with(mixins) { clearfix() }
 // Clear the float from controls
}

// Float to collapse white-space for proper grid alignment
.controls-row [class*="span"] // Redeclare the fluid grid collapse since we undo the float for inputs
rule(".row-fluid .controls-row [class*="span"]") {
  float: left;
}
// Explicity set top padding on all checkboxes/radios, not just first-child
rule(".controls-row .checkbox[class*="span"] .controls-row .radio[class*="span"]") {
  paddingTop = 5.px
}




// DISABLED STATE

// Disabled and read-only inputs
rule("input[disabled] select[disabled] textarea[disabled] input[readonly] select[readonly] textarea[readonly]") {
  cursor: not-allowed;
  backgroundColor = vars.inputDisabledBackground
}
// Explicitly reset the colors here
rule("input[type="radio"][disabled] input[type="checkbox"][disabled] input[type="radio"][readonly] input[type="checkbox"][readonly]") {
  background-color: transparent;
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
rule("input:focus:invalid textarea:focus:invalid select:focus:invalid") {
  color: #b94a48;
  borderColor = Color("#ee5f5b")
  &:focus {
    border-color: darken(#ee5f5b, 10%);
    vars.shadow: 0px 0px 6px lighten(#ee5f5b, 20%);
    with(mixins) { boxShadow(vars.shadow) }
  }
}



// FORM ACTIONS
rule(".form-actions") {
  padding: (vars.baseLineHeight-1) 20px vars.baseLineHeight;
  marginTop = vars.baseLineHeight
  marginBottom = vars.baseLineHeight
  backgroundColor = vars.formActionsBackground
  borderTop = Border(1.px, BorderStyle.solid, Color(solid))
  with(mixins) { clearfix() }
 // Adding clearfix to allow for .pull-right button containers
}



// HELP TEXT
// ---------
rule(".help-block .help-inline") {
  color: lighten(vars.textColor, 15%);
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
rule(".input-append .input-prepend") {
  display = Display.inlineBlock
  marginBottom = vars.baseLineHeight / 2
  verticalAlign = VerticalAlign.middle
  fontSize = 0.px
 // white space collapse hack
  whiteSpace = WhiteSpace.nowrap
 // Prevent span and input from separating

  // Reset the white space collapse hack
  input select .uneditable-input .dropdown-menu .popover {
    fontSize = vars.baseFontSize
  }

rule("  input select .uneditable-input") {
    position = Position.relative
 // placed here by default so that on :focus we can place the input above the .add-on for full border and box-shadow goodness
    marginBottom = 0.px // prevent bottom margin from screwing up alignment in stacked forms
    declarations["*marginLeft"] = 0.px
    verticalAlign = VerticalAlign.top
    with(mixins) { borderRadius(0px vars.inputBorderRadius vars.inputBorderRadius 0px) }
    // Make input on top when focused so blue border and shadow always show
    &:focus {
      zIndex = 2
    }
  }
  .add-on {
    display = Display.inlineBlock
    width: auto;
    height: vars.baseLineHeight;
    min-width: 16px;
    padding = Padding(4.px, 5.px)
    fontSize = vars.baseFontSize
    font-weight: normal;
    lineHeight = vars.baseLineHeight
    text-align: center;
    text-shadow: 0px 1px 0px vars.white;
    backgroundColor = vars.grayLighter
    border = Border(1.px, BorderStyle.solid, Color(#ccc))
  }
  .add-on .btn .btn-group > .dropdown-toggle {
    verticalAlign = VerticalAlign.top
    with(mixins) { borderRadius(0px) }
  }
  .active {
    background-color: lighten(vars.green, 30);
    borderColor =  vars.green
  }
}

rule(".input-prepend") {
  .add-on .btn {
    marginRight = -1.px
  }
  .add-on:first-child .btn:first-child {
    // FYI, `.btn:first-child` accounts for a button group that's prepended
    with(mixins) { borderRadius(vars.inputBorderRadius 0px 0px vars.inputBorderRadius) }
  }
}

rule(".input-append") {
  input select .uneditable-input {
    with(mixins) { borderRadius(vars.inputBorderRadius 0px 0px vars.inputBorderRadius) }
    + .btn-group .btn:last-child {
      with(mixins) { borderRadius(0px vars.inputBorderRadius vars.inputBorderRadius 0px) }
    }
  }
  .add-on .btn .btn-group {
    marginLeft = -1.px
  }
  .add-on:last-child .btn:last-child .btn-group:last-child > .dropdown-toggle {
    with(mixins) { borderRadius(0px vars.inputBorderRadius vars.inputBorderRadius 0px) }
  }
}

// Remove all border-radius for inputs with both prepend and append
rule(".input-prepend.input-append") {
  input select .uneditable-input {
    with(mixins) { borderRadius(0px) }
    + .btn-group .btn {
      with(mixins) { borderRadius(0px vars.inputBorderRadius vars.inputBorderRadius 0px) }
    }
  }
  .add-on:first-child .btn:first-child {
    marginRight = -1.px
    with(mixins) { borderRadius(vars.inputBorderRadius 0px 0px vars.inputBorderRadius) }
  }
  .add-on:last-child .btn:last-child {
    marginLeft = -1.px
    with(mixins) { borderRadius(0px vars.inputBorderRadius vars.inputBorderRadius 0px) }
  }
  .btn-group:first-child {
    marginLeft = 0.px
  }
}




// SEARCH FORM
rule("input.search-query") {
  paddingRight = 14.px
  padding-right: 4px \9;
  paddingLeft = 14.px
  padding-left: 4px \9;
 /* IE7-8 doesn't have border-radius, so don't indent the padding */
  marginBottom = 0.px // Remove the default margin on all inputs
  with(mixins) { borderRadius(15px) }
}

/* Allow for input prepend/append in search forms */
rule(".form-search .input-append .search-query .form-search .input-prepend .search-query") {
  with(mixins) { borderRadius(0px) }
 // Override due to specificity
}

rule(".form-search .input-append .search-query") {
  with(mixins) { borderRadius(14px 0px 0px 14px) }
}

rule(".form-search .input-append .btn") {
  with(mixins) { borderRadius(0px 14px 14px 0px) }
}

rule(".form-search .input-prepend .search-query") {
  with(mixins) { borderRadius(0px 14px 14px 0px) }
}

rule(".form-search .input-prepend .btn") {
  with(mixins) { borderRadius(14px 0px 0px 14px) }
}




// HORIZONTAL & VERTICAL FORMS

// Common properties
rule(".form-search .form-inline .form-horizontal") {
  input textarea select .help-inline .uneditable-input .input-prepend .input-append {
    display = Display.inlineBlock
    with(mixins) { ie7InlineBlock() }
    marginBottom = 0.px
    verticalAlign = VerticalAlign.middle
  }
  // Re-hide hidden elements due to specifity
  .hide {
    display = Display.none
  }
}

rule(".form-search label .form-inline label .form-search .btn-group .form-inline .btn-group") {
  display = Display.inlineBlock
}
// Remove margin for input-prepend/-append
rule(".form-search .input-append .form-inline .input-append .form-search .input-prepend .form-inline .input-prepend") {
  marginBottom = 0.px
}
// Inline checkbox/radio labels (remove padding on left)
rule(".form-search .radio .form-search .checkbox .form-inline .radio .form-inline .checkbox") {
  paddingLeft = 0.px
  marginBottom = 0.px
  verticalAlign = VerticalAlign.middle
}
// Remove float and margin, set to inline-block
rule(".form-search .radio input[type="radio"] .form-search .checkbox input[type="checkbox"] .form-inline .radio input[type="radio"] .form-inline .checkbox input[type="checkbox"]") {
  float: left;
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
  -webkit-margin-top-collapse: separate;
}

// Horizontal-specific styles
rule(".form-horizontal") {
  // Increase spacing between groups
  .control-group {
    marginBottom = vars.baseLineHeight
    with(mixins) { clearfix() }
  }
  // Float the labels left
  .control-label {
    float: left;
    width: vars.horizontalComponentOffset-20;
    paddingTop = 5.px
    text-align: right;
  }
  // Move over all input controls and content
  .controls {
    // Super jank IE7 fix to ensure the inputs in .input-append and input-prepend
    // don't inherit the margin of the parent, in this case .controls
    declarations["*display"] = Display.inlineBlock
    declarations["*paddingLeft"] = 20.px
    marginLeft = vars.horizontalComponentOffset
    declarations["*marginLeft"] = 0.px
    &:first-child {
      declarations["*paddingLeft"] = vars.horizontalComponentOffset
    }
  }
  // Remove bottom margin on block level help text since that's accounted for on .control-group
  .help-block {
    marginBottom = 0.px
  }
  // And apply it only to .help-block instances that follow a form control
  input select textarea .uneditable-input .input-prepend .input-append {
    + .help-block {
      marginTop = vars.baseLineHeight / 2
    }
  }
  // Move over buttons in .form-actions to align with .controls
  .form-actions {
    paddingLeft = vars.horizontalComponentOffset
  }
}
    */}


    override fun CssBuilder.grid(){/*
// Fixed (940px)
#grid > .core(vars.gridColumnWidth, vars.gridGutterWidth);

// Fluid (940px)
#grid > .fluid(vars.fluidGridColumnWidth, vars.fluidGridGutterWidth);

// Reset utility classes due to specificity
rule("[class*="span"].hide .row-fluid [class*="span"].hide") {
  display = Display.none
}

rule("[class*="span"].pull-right .row-fluid [class*="span"].pull-right") {
  float: right;
}
    */}


    override fun CssBuilder.heroUnit(){/*
rule(".hero-unit") {
  padding = Padding(60.px)
  marginBottom = 30.px
  fontSize = 18.px
  font-weight: 200;
  line-height: vars.baseLineHeight * 1.5;
  color = vars.heroUnitLeadColor
  backgroundColor = vars.heroUnitBackground
  with(mixins) { borderRadius(6px) }
  h1 {
    marginBottom = 0.px
    fontSize = 60.px
    lineHeight = 1.px
    color = vars.heroUnitHeadingColor
    letter-spacing: -1px;
  }
  li {
    line-height: vars.baseLineHeight * 1.5;
 // Reset since we specify in type.less
  }
}
    */}


    override fun CssBuilder.labelsBadges(){/*
// Base classes
rule(".label .badge") {
  display = Display.inlineBlock
  padding = Padding(2.px, 4.px)
  fontSize = vars.baseFontSize * .846
  font-weight: bold;
  line-height: 14px;
 // ensure proper line-height if floated
  color = vars.white
  verticalAlign = VerticalAlign.baseline
  whiteSpace = WhiteSpace.nowrap
  text-shadow: 0px -1px 0px rgba(0,0,0,.25);
  backgroundColor = vars.grayLight
}
// Set unique padding and border-radii
rule(".label") {
  with(mixins) { borderRadius(3px) }
}

rule(".badge") {
  paddingLeft = 9.px
  paddingRight = 9.px
  with(mixins) { borderRadius(9px) }
}

// Empty labels/badges collapse
rule(".label .badge") {
  &:empty {
    display = Display.none
  }
}

// Hover/focus state, but only for links
a {
  &.label:hover &.label:focus &.badge:hover &.badge:focus {
    color = vars.white
    text-decoration: none;
    cursor = Cursor.pointer
  }
}

// Colors
// Only give background-color difference to links (and to simplify, we don't qualifty with `a` but [href] attribute)
rule(".label .badge") {
  // Important (red)
  &-important         { backgroundColor = vars.errorText
 }
  &-important[href]   { background-color: darken(vars.errorText, 10%);
 }
  // Warnings (orange)
  &-warning           { backgroundColor = vars.orange
 }
  &-warning[href]     { background-color: darken(vars.orange, 10%);
 }
  // Success (green)
  &-success           { backgroundColor = vars.successText
 }
  &-success[href]     { background-color: darken(vars.successText, 10%);
 }
  // Info (turquoise)
  &-info              { backgroundColor = vars.infoText
 }
  &-info[href]        { background-color: darken(vars.infoText, 10%);
 }
  // Inverse (black)
  &-inverse           { backgroundColor = vars.grayDark
 }
  &-inverse[href]     { background-color: darken(vars.grayDark, 10%);
 }
}

// Quick fix for labels/badges in buttons
rule(".btn") {
  .label .badge {
    position = Position.relative
    top = -1.px
  }
}

rule(".btn-mini") {
  .label .badge {
    top = 0.px
  }
}
    */}


    override fun CssBuilder.layouts(){/*
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
    */}


    override fun CssBuilder.media(){/*
// Common styles

// Clear the floats
rule(".media .media-body") {
  overflow: hidden;
  declarations[*overflow] = "visible"
  zoom: 1;
}

// Proper spacing between instances of .media
rule(".media .media .media") {
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
  list-style: none;
}
    */}


    override fun CssBuilder.mixins(){/*
// UTILITY MIXINS

// Clearfix
// --------
// For clearing floats like a boss h5bp.com/q
rule(".clearfix") {
  declarations[*zoom] = "1"
  &:before &:after {
    display = Display.table
    content: "";
    // Fixes Opera/contenteditable bug:
    // http://nicolasgallagher.com/micro-clearfix-hack/#comment-36952
    line-height: 0px;
  }
  &:after {
    clear: both;
  }
}

// Webkit-style focus
fun CssBuilder.tabFocus()
  // Default
  outline: thin dotted #333;
  // Webkit
  outline: 5px auto -webkit-focus-ring-color;
  outline-offset: -2px;
}

// Center-align a block level element
fun CssBuilder.centerBlock()
  display = Display.block
  marginLeft = LinearDimension.auto
  marginRight = LinearDimension.auto
}

// IE7 inline-block
fun CssBuilder.ie7InlineBlock()
  declarations["*display"] = Display.inline /* IE7 inline-block hack */
  declarations[*zoom] = "1"
}

// IE7 likes to collapse whitespace on either side of the inline-block elements.
// Ems because we're attempting to match the width of a space character. Left
// version is for form buttons, which typically come after other elements, and
// right version is for icons, which come before. Applying both is ok, but it will
// mean that space between those elements will be .6em (~2 space characters) in IE7 // instead of the 1 space in other browsers.
fun CssBuilder.ie7RestoreLeftWhitespace()
  declarations[*margin-left] = ".3em"
rule("  &:first-child") {
    declarations["*marginLeft"] = 0.px
  }
}

fun CssBuilder.ie7RestoreRightWhitespace()
  declarations[*margin-right] = ".3em"
}

// Sizing shortcuts
fun CssBuilder.size(vars.height, vars.width)
  width: vars.width;
  height: vars.height;
}
fun CssBuilder.square(vars.size)
  with(mixins) { size(vars.size, vars.size) }
}

// Placeholder text
fun CssBuilder.placeholder(vars.color: vars.placeholderText)
  &:-moz-placeholder {
    color = vars.color
  }
  &:-ms-input-placeholder {
    color = vars.color
  }
  &::-webkit-input-placeholder {
    color = vars.color
  }
}

// Text overflow
// Requires inline-block or block for proper styling
fun CssBuilder.textOverflow()
  overflow: hidden;
  text-overflow: ellipsis;
  whiteSpace = WhiteSpace.nowrap
}

// CSS image replacement
// Source: https://github.com/h5bp/html5-boilerplate/commit/aa0396eae757
rule(".hide-text") {
  font: 0/0px a;
  color = Color.transparent
  text-shadow: none;
  background-color: transparent;
  border: 0px;
}


// FONTS
rule("#font") {
  #family {
    fun CssBuilder.serif()
      font-family: vars.serifFontFamily;
    }
    fun CssBuilder.sansSerif()
      font-family: vars.sansFontFamily;
    }
    fun CssBuilder.monospace()
      font-family: vars.monoFontFamily;
    }
  }
  fun CssBuilder.shorthand(vars.size: vars.baseFontSize, vars.weight: normal, vars.lineHeight: vars.baseLineHeight)
    fontSize = vars.size
    font-weight: vars.weight;
    lineHeight = vars.lineHeight
  }
  fun CssBuilder.serif(vars.size: vars.baseFontSize, vars.weight: normal, vars.lineHeight: vars.baseLineHeight)
    #font > #family > .serif;
    #font > .shorthand(vars.size, vars.weight, vars.lineHeight);
  }
  fun CssBuilder.sansSerif(vars.size: vars.baseFontSize, vars.weight: normal, vars.lineHeight: vars.baseLineHeight)
    #font > #family > .sans-serif;
    #font > .shorthand(vars.size, vars.weight, vars.lineHeight);
  }
  fun CssBuilder.monospace(vars.size: vars.baseFontSize, vars.weight: normal, vars.lineHeight: vars.baseLineHeight)
    #font > #family > .monospace;
    #font > .shorthand(vars.size, vars.weight, vars.lineHeight);
  }
}


// FORMS

// Block level inputs
rule(".input-block-level") {
  display = Display.block
  width: 100%;
  min-height: vars.inputHeight;
 // Make inputs at least the height of their button counterpart (base line-height + padding + border)
  with(mixins) { boxSizing(border-box) }
 // Makes inputs behave like true block-level elements
}



// Mixin for form field states
fun CssBuilder.formFieldState(vars.textColor: #555, vars.borderColor: #ccc, vars.backgroundColor: #f5f5f5)
  // Set the text color
  .control-label .help-block .help-inline {
    color = vars.textColor
  }
  // Style inputs accordingly
  .checkbox .radio input select textarea {
    color = vars.textColor
  }
  input select textarea {
    borderColor =  vars.borderColor
    with(mixins) { boxShadow(inset 0px 1px 1px rgba(0,0,0,.075)) }
 // Redeclare so transitions work
    &:focus {
      border-color: darken(vars.borderColor, 10%);
      vars.shadow: inset 0px 1px 1px rgba(0,0,0,.075), 0px 0px 6px lighten(vars.borderColor, 20%);
      with(mixins) { boxShadow(vars.shadow) }
    }
  }
  // Give a small background color for input-prepend/-append
  .input-prepend .add-on .input-append .add-on {
    color = vars.textColor
    backgroundColor = vars.backgroundColor
    borderColor =  vars.textColor
  }
}



// CSS3 PROPERTIES

// Border Radius
fun CssBuilder.borderRadius(vars.radius)
  -webkit-border-radius: vars.radius;
     -moz-border-radius: vars.radius;
          border-radius: vars.radius;
}

// Single Corner Border Radius
fun CssBuilder.borderTopLeftRadius(vars.radius)
  -webkit-border-top-left-radius: vars.radius;
      -moz-border-radius-topleft: vars.radius;
          border-top-left-radius: vars.radius;
}
fun CssBuilder.borderTopRightRadius(vars.radius)
  -webkit-border-top-right-radius: vars.radius;
      -moz-border-radius-topright: vars.radius;
          border-top-right-radius: vars.radius;
}
fun CssBuilder.borderBottomRightRadius(vars.radius)
  -webkit-border-bottom-right-radius: vars.radius;
      -moz-border-radius-bottomright: vars.radius;
          border-bottom-right-radius: vars.radius;
}
fun CssBuilder.borderBottomLeftRadius(vars.radius)
  -webkit-border-bottom-left-radius: vars.radius;
      -moz-border-radius-bottomleft: vars.radius;
          border-bottom-left-radius: vars.radius;
}

// Single Side Border Radius
fun CssBuilder.borderTopRadius(vars.radius)
  with(mixins) { borderTopRightRadius(vars.radius) }
  with(mixins) { borderTopLeftRadius(vars.radius) }
}
fun CssBuilder.borderRightRadius(vars.radius)
  with(mixins) { borderTopRightRadius(vars.radius) }
  with(mixins) { borderBottomRightRadius(vars.radius) }
}
fun CssBuilder.borderBottomRadius(vars.radius)
  with(mixins) { borderBottomRightRadius(vars.radius) }
  with(mixins) { borderBottomLeftRadius(vars.radius) }
}
fun CssBuilder.borderLeftRadius(vars.radius)
  with(mixins) { borderTopLeftRadius(vars.radius) }
  with(mixins) { borderBottomLeftRadius(vars.radius) }
}

// Drop shadows
fun CssBuilder.boxShadow(vars.shadow)
  -webkit-box-shadow: vars.shadow;
     -moz-box-shadow: vars.shadow;
          box-shadow: vars.shadow;
}

// Transitions
fun CssBuilder.transition(vars.transition)
  -webkit-transition: vars.transition;
     -moz-transition: vars.transition;
       -o-transition: vars.transition;
          transition: vars.transition;
}
fun CssBuilder.transitionDelay(vars.transition-delay)
  -webkit-transition-delay: vars.transition-delay;
     -moz-transition-delay: vars.transition-delay;
       -o-transition-delay: vars.transition-delay;
          transition-delay: vars.transition-delay;
}
fun CssBuilder.transitionDuration(vars.transition-duration)
  -webkit-transition-duration: vars.transition-duration;
     -moz-transition-duration: vars.transition-duration;
       -o-transition-duration: vars.transition-duration;
          transition-duration: vars.transition-duration;
}

// Transformations
fun CssBuilder.rotate(vars.degrees)
  -webkit-transform: rotate(vars.degrees);
     -moz-transform: rotate(vars.degrees);
      -ms-transform: rotate(vars.degrees);
       -o-transform: rotate(vars.degrees);
          transform: rotate(vars.degrees);
}
fun CssBuilder.scale(vars.ratio)
  -webkit-transform: scale(vars.ratio);
     -moz-transform: scale(vars.ratio);
      -ms-transform: scale(vars.ratio);
       -o-transform: scale(vars.ratio);
          transform: scale(vars.ratio);
}
fun CssBuilder.translate(vars.x, vars.y)
  -webkit-transform: translate(vars.x, vars.y);
     -moz-transform: translate(vars.x, vars.y);
      -ms-transform: translate(vars.x, vars.y);
       -o-transform: translate(vars.x, vars.y);
          transform: translate(vars.x, vars.y);
}
fun CssBuilder.skew(vars.x, vars.y)
  -webkit-transform: skew(vars.x, vars.y);
     -moz-transform: skew(vars.x, vars.y);
      -ms-transform: skewX(vars.x) skewY(vars.y);
 // See https://github.com/twbs/bootstrap/issues/4885
       -o-transform: skew(vars.x, vars.y);
          transform: skew(vars.x, vars.y);
  -webkit-backface-visibility: hidden;
 // See https://github.com/twbs/bootstrap/issues/5319
}
fun CssBuilder.translate3d(vars.x, vars.y, vars.z)
  -webkit-transform: translate3d(vars.x, vars.y, vars.z);
     -moz-transform: translate3d(vars.x, vars.y, vars.z);
       -o-transform: translate3d(vars.x, vars.y, vars.z);
          transform: translate3d(vars.x, vars.y, vars.z);
}

// Backface visibility
// Prevent browsers from flickering when using CSS 3D transforms.
// Default value is `visible`, but can be changed to `hidden
// See git pull https://github.com/dannykeane/bootstrap.git backface-visibility for examples
.backfaceVisibility(vars.visibility){
	-webkit-backface-visibility: vars.visibility;
	   -moz-backface-visibility: vars.visibility;
	        backface-visibility: vars.visibility;
}

// Background clipping
// Heads up: FF 3.6 and under need "padding" instead of "padding-box"
fun CssBuilder.backgroundClip(vars.clip)
  -webkit-background-clip: vars.clip;
     -moz-background-clip: vars.clip;
          background-clip: vars.clip;
}

// Background sizing
fun CssBuilder.backgroundSize(vars.size)
  -webkit-background-size: vars.size;
     -moz-background-size: vars.size;
       -o-background-size: vars.size;
          background-size: vars.size;
}


// Box sizing
fun CssBuilder.boxSizing(vars.boxmodel)
  -webkit-box-sizing: vars.boxmodel;
     -moz-box-sizing: vars.boxmodel;
          box-sizing: vars.boxmodel;
}

// User select
// For selecting text on the page
fun CssBuilder.userSelect(vars.select)
  -webkit-user-select: vars.select;
     -moz-user-select: vars.select;
      -ms-user-select: vars.select;
       -o-user-select: vars.select;
          user-select: vars.select;
}

// Resize anything
fun CssBuilder.resizable(vars.direction)
  resize: vars.direction;
 // Options: horizontal, vertical, both
  overflow: auto;
 // Safari fix
}

// CSS3 Content Columns
fun CssBuilder.contentColumns(vars.columnCount, vars.columnGap: vars.gridGutterWidth)
  -webkit-column-count: vars.columnCount;
     -moz-column-count: vars.columnCount;
          column-count: vars.columnCount;
  -webkit-column-gap: vars.columnGap;
     -moz-column-gap: vars.columnGap;
          column-gap: vars.columnGap;
}

// Optional hyphenation
fun CssBuilder.hyphens(vars.mode: auto)
  word-wrap: break-word;
  -webkit-hyphens: vars.mode;
     -moz-hyphens: vars.mode;
      -ms-hyphens: vars.mode;
       -o-hyphens: vars.mode;
          hyphens: vars.mode;
}

// Opacity
fun CssBuilder.opacity(vars.opacity)
  opacity: vars.opacity / 100;
  filter: ~"alpha(opacity=@{opacity})";
}



// BACKGROUNDS

// Add an alphatransparency value to any background or border color (via Elyse Holladay)
rule("#translucent") {
  fun CssBuilder.background(vars.color: vars.white, vars.alpha: 1)
    background-color: hsla(hue(vars.color), saturation(vars.color), lightness(vars.color), vars.alpha);
  }
  fun CssBuilder.border(vars.color: vars.white, vars.alpha: 1)
    border-color: hsla(hue(vars.color), saturation(vars.color), lightness(vars.color), vars.alpha);
    with(mixins) { backgroundClip(padding-box) }
  }
}

// Gradient Bar Colors for buttons and alerts
fun CssBuilder.gradientBar(vars.primaryColor, vars.secondaryColor, vars.textColor: #fff, vars.textShadow: 0px -1px 0px rgba(0,0,0,.25))
  color = vars.textColor
  text-shadow: vars.textShadow;
  #gradient > .vertical(vars.primaryColor, vars.secondaryColor);
  border-color: vars.secondaryColor vars.secondaryColor darken(vars.secondaryColor, 15%);
  border-color: rgba(0,0,0,.1) rgba(0,0,0,.1) fadein(rgba(0,0,0,.1), 15%);
}

// Gradients
rule("#gradient") {
  fun CssBuilder.horizontal(vars.startColor: #555, vars.endColor: #333)
    backgroundColor = vars.endColor
    background-image: -moz-linear-gradient(left, vars.startColor, vars.endColor);
 // FF 3.6+
    background-image: -webkit-gradient(linear, 0px 0, 100% 0, from(vars.startColor), to(vars.endColor));
 // Safari 4+, Chrome 2+
    background-image: -webkit-linear-gradient(left, vars.startColor, vars.endColor);
 // Safari 5.1+, Chrome 10+
    background-image: -o-linear-gradient(left, vars.startColor, vars.endColor);
 // Opera 11.10
    background-image: linear-gradient(to right, vars.startColor, vars.endColor);
 // Standard, IE10
    background-repeat: repeat-x;
    filter: e(%("progid:DXImageTransform.Microsoft.gradient(startColorstr='%d', endColorstr='%d', GradientType=1)",argb(vars.startColor),argb(vars.endColor)));
 // IE9 and down
  }
  fun CssBuilder.vertical(vars.startColor: #555, vars.endColor: #333)
    background-color: mix(vars.startColor, vars.endColor, 60%);
    background-image: -moz-linear-gradient(top, vars.startColor, vars.endColor);
 // FF 3.6+
    background-image: -webkit-gradient(linear, 0px 0, 0px 100%, from(vars.startColor), to(vars.endColor));
 // Safari 4+, Chrome 2+
    background-image: -webkit-linear-gradient(top, vars.startColor, vars.endColor);
 // Safari 5.1+, Chrome 10+
    background-image: -o-linear-gradient(top, vars.startColor, vars.endColor);
 // Opera 11.10
    background-image: linear-gradient(to bottom, vars.startColor, vars.endColor);
 // Standard, IE10
    background-repeat: repeat-x;
    filter: e(%("progid:DXImageTransform.Microsoft.gradient(startColorstr='%d', endColorstr='%d', GradientType=0px)",argb(vars.startColor),argb(vars.endColor)));
 // IE9 and down
  }
  fun CssBuilder.directional(vars.startColor: #555, vars.endColor: #333, vars.deg: 45deg)
    backgroundColor = vars.endColor
    background-repeat: repeat-x;
    background-image: -moz-linear-gradient(vars.deg, vars.startColor, vars.endColor);
 // FF 3.6+
    background-image: -webkit-linear-gradient(vars.deg, vars.startColor, vars.endColor);
 // Safari 5.1+, Chrome 10+
    background-image: -o-linear-gradient(vars.deg, vars.startColor, vars.endColor);
 // Opera 11.10
    background-image: linear-gradient(vars.deg, vars.startColor, vars.endColor);
 // Standard, IE10
  }
  fun CssBuilder.horizontalThreeColors(vars.startColor: #00b3ee, vars.midColor: #7a43b6, vars.colorStop: 50%, vars.endColor: #c3325f)
    background-color: mix(vars.midColor, vars.endColor, 80%);
    background-image: -webkit-gradient(left, linear, 0px 0, 0px 100%, from(vars.startColor), color-stop(vars.colorStop, vars.midColor), to(vars.endColor));
    background-image: -webkit-linear-gradient(left, vars.startColor, vars.midColor vars.colorStop, vars.endColor);
    background-image: -moz-linear-gradient(left, vars.startColor, vars.midColor vars.colorStop, vars.endColor);
    background-image: -o-linear-gradient(left, vars.startColor, vars.midColor vars.colorStop, vars.endColor);
    background-image: linear-gradient(to right, vars.startColor, vars.midColor vars.colorStop, vars.endColor);
    background-repeat: no-repeat;
    filter: e(%("progid:DXImageTransform.Microsoft.gradient(startColorstr='%d', endColorstr='%d', GradientType=0px)",argb(vars.startColor),argb(vars.endColor)));
 // IE9 and down, gets no color-stop at all for proper fallback
  }

  fun CssBuilder.verticalThreeColors(vars.startColor: #00b3ee, vars.midColor: #7a43b6, vars.colorStop: 50%, vars.endColor: #c3325f)
    background-color: mix(vars.midColor, vars.endColor, 80%);
    background-image: -webkit-gradient(linear, 0px 0, 0px 100%, from(vars.startColor), color-stop(vars.colorStop, vars.midColor), to(vars.endColor));
    background-image: -webkit-linear-gradient(vars.startColor, vars.midColor vars.colorStop, vars.endColor);
    background-image: -moz-linear-gradient(top, vars.startColor, vars.midColor vars.colorStop, vars.endColor);
    background-image: -o-linear-gradient(vars.startColor, vars.midColor vars.colorStop, vars.endColor);
    background-image: linear-gradient(vars.startColor, vars.midColor vars.colorStop, vars.endColor);
    background-repeat: no-repeat;
    filter: e(%("progid:DXImageTransform.Microsoft.gradient(startColorstr='%d', endColorstr='%d', GradientType=0px)",argb(vars.startColor),argb(vars.endColor)));
 // IE9 and down, gets no color-stop at all for proper fallback
  }
  fun CssBuilder.radial(vars.innerColor: #555, vars.outerColor: #333)
    backgroundColor = vars.outerColor
    background-image: -webkit-gradient(radial, center center, 0, center center, 460, from(vars.innerColor), to(vars.outerColor));
    background-image: -webkit-radial-gradient(circle, vars.innerColor, vars.outerColor);
    background-image: -moz-radial-gradient(circle, vars.innerColor, vars.outerColor);
    background-image: -o-radial-gradient(circle, vars.innerColor, vars.outerColor);
    background-repeat: no-repeat;
  }
  fun CssBuilder.striped(vars.color: #555, vars.angle: 45deg)
    backgroundColor = vars.color
    background-image: -webkit-gradient(linear, 0px 100%, 100% 0, color-stop(.25, rgba(255,255,255,.15)), color-stop(.25, transparent), color-stop(.5, transparent), color-stop(.5, rgba(255,255,255,.15)), color-stop(.75, rgba(255,255,255,.15)), color-stop(.75, transparent), to(transparent));
    background-image: -webkit-linear-gradient(vars.angle, rgba(255,255,255,.15) 25%, transparent 25%, transparent 50%, rgba(255,255,255,.15) 50%, rgba(255,255,255,.15) 75%, transparent 75%, transparent);
    background-image: -moz-linear-gradient(vars.angle, rgba(255,255,255,.15) 25%, transparent 25%, transparent 50%, rgba(255,255,255,.15) 50%, rgba(255,255,255,.15) 75%, transparent 75%, transparent);
    background-image: -o-linear-gradient(vars.angle, rgba(255,255,255,.15) 25%, transparent 25%, transparent 50%, rgba(255,255,255,.15) 50%, rgba(255,255,255,.15) 75%, transparent 75%, transparent);
    background-image: linear-gradient(vars.angle, rgba(255,255,255,.15) 25%, transparent 25%, transparent 50%, rgba(255,255,255,.15) 50%, rgba(255,255,255,.15) 75%, transparent 75%, transparent);
  }
}
// Reset filters for IE
fun CssBuilder.resetFilter()
  filter: e(%("progid:DXImageTransform.Microsoft.gradient(enabled = false)"));
}



// COMPONENT MIXINS

// Horizontal dividers
// Dividers (basically an hr) within dropdowns and nav lists
fun CssBuilder.navDivider(vars.top: #e5e5e5, vars.bottom: vars.white)
  // IE7 needs a set width since we gave a height. Restricting just
  // to IE7 to keep the 1px left/right space in other browsers.
  // It is unclear where IE is getting the extra space that we need
  // to negative-margin away, but so it goes.
  declarations[*width] = "100%"
  height: 1px;
  margin: ((vars.baseLineHeight / 2)-1) 1px;
 // 8px 1px
  declarations[*margin] = "-5px 0px 5px"
  overflow: hidden;
  backgroundColor = vars.top
  borderBottom = Border(1.px, BorderStyle.solid, Color(solid))
}

// Button backgrounds
fun CssBuilder.buttonBackground(vars.startColor, vars.endColor, vars.textColor: #fff, vars.textShadow: 0px -1px 0px rgba(0,0,0,.25))
  // gradientBar will set the background to a pleasing blend of these, to support IE<=9
  with(mixins) { gradientBar(vars.startColor, vars.endColor, vars.textColor, vars.textShadow) }
  declarations["*backgroundColor"] = vars.endColor
 /* Darken IE7 buttons by default so they stand out more given they won't have borders */
  with(mixins) { resetFilter() }

  // in these cases the gradient won't cover the background, so we override
  &:hover, &:focus, &:active, &.active, &.disabled, &[disabled] {
    color = vars.textColor
    backgroundColor = vars.endColor
    declarations[*background-color] = "darken(vars.endColor, 5%)"
  }

  // IE 7 + 8 can't handle box-shadow to show active, so we darken a bit ourselves
  &:active &.active {
    background-color: darken(vars.endColor, 10%) e("\9");
  }
}

// Navbar vertical align
// Vertically center elements in the navbar.
// Example: an element has a height of 30px, so write out `.navbarVerticalAlign(30px);
` to calculate the appropriate top margin.
fun CssBuilder.navbarVerticalAlign(vars.elementHeight)
  margin-top: (vars.navbarHeight-vars.elementHeight) / 2;
}



// Grid System

// Centered container element
fun CssBuilder.containerFixed()
  marginRight = LinearDimension.auto
  marginLeft = LinearDimension.auto
  with(mixins) { clearfix() }
}

// Table columns
fun CssBuilder.tableColumns(vars.columnSpan: 1)
  float: none;
 // undo default grid column styles
  width: ((vars.gridColumnWidth) * vars.columnSpan) + (vars.gridGutterWidth * (vars.columnSpan-1))-16;
 // 16 is total padding on left and right of table cells
  marginLeft = 0.px // undo default grid column styles
}

// Make a Grid
// Use .makeRow and .makeColumn to assign semantic layouts grid system behavior
fun CssBuilder.makeRow()
  margin-left: vars.gridGutterWidth * -1;
  with(mixins) { clearfix() }
}
fun CssBuilder.makeColumn(vars.columns: 1, vars.offset: 0px)
  float: left;
  margin-left: (vars.gridColumnWidth * vars.offset) + (vars.gridGutterWidth * (vars.offset-1)) + (vars.gridGutterWidth * 2);
  width: (vars.gridColumnWidth * vars.columns) + (vars.gridGutterWidth * (vars.columns-1));
}

// The Grid
rule("#grid") {

  .core (vars.gridColumnWidth, vars.gridGutterWidth) {

    .spanX (vars.index) when (vars.index > 0px) {
      .span@{index} { .span(vars.index);
 }
      with(mixins) { spanX(vars.index-1) }
    }
    .spanX (0px) {}

    .offsetX (vars.index) when (vars.index > 0px) {
      .offset@{index} { .offset(vars.index);
 }
      with(mixins) { offsetX(vars.index-1) }
    }
    .offsetX (0px) {}

    .offset (vars.columns) {
      margin-left: (vars.gridColumnWidth * vars.columns) + (vars.gridGutterWidth * (vars.columns + 1));
    }

    .span (vars.columns) {
      width: (vars.gridColumnWidth * vars.columns) + (vars.gridGutterWidth * (vars.columns-1));
    }

rule("    .row") {
      margin-left: vars.gridGutterWidth * -1;
      with(mixins) { clearfix() }
    }

rule("    [class*="span"]") {
      float: left;
      min-height: 1px;
 // prevent collapsing columns
      marginLeft = vars.gridGutterWidth
    }

    // Set the container width, and override it for fixed navbars in media queries
    .container .navbar-static-top .container .navbar-fixed-top .container .navbar-fixed-bottom .container { .span(vars.gridColumns);
 }

    // generate .spanX and .offsetX
    .spanX (vars.gridColumns);
    .offsetX (vars.gridColumns);

  }

  .fluid (vars.fluidGridColumnWidth, vars.fluidGridGutterWidth) {

    .spanX (vars.index) when (vars.index > 0px) {
      .span@{index} { .span(vars.index);
 }
      with(mixins) { spanX(vars.index-1) }
    }
    .spanX (0px) {}

    .offsetX (vars.index) when (vars.index > 0px) {
      .offset@{index} { .offset(vars.index);
 }
      .offset@{index}:first-child { .offsetFirstChild(vars.index);
 }
      with(mixins) { offsetX(vars.index-1) }
    }
    .offsetX (0px) {}

    .offset (vars.columns) {
      margin-left: (vars.fluidGridColumnWidth * vars.columns) + (vars.fluidGridGutterWidth * (vars.columns-1)) + (vars.fluidGridGutterWidth*2);
  	  declarations[*margin-left] = "(vars.fluidGridColumnWidth * vars.columns) + (vars.fluidGridGutterWidth * (vars.columns-1))-(.5 / vars.gridRowWidth * 100 * 1%) + (vars.fluidGridGutterWidth*2)-(.5 / vars.gridRowWidth * 100 * 1%)"
    }

    .offsetFirstChild (vars.columns) {
      margin-left: (vars.fluidGridColumnWidth * vars.columns) + (vars.fluidGridGutterWidth * (vars.columns-1)) + (vars.fluidGridGutterWidth);
      declarations[*margin-left] = "(vars.fluidGridColumnWidth * vars.columns) + (vars.fluidGridGutterWidth * (vars.columns-1))-(.5 / vars.gridRowWidth * 100 * 1%) + vars.fluidGridGutterWidth-(.5 / vars.gridRowWidth * 100 * 1%)"
    }

    .span (vars.columns) {
      width: (vars.fluidGridColumnWidth * vars.columns) + (vars.fluidGridGutterWidth * (vars.columns-1));
      declarations[*width] = "(vars.fluidGridColumnWidth * vars.columns) + (vars.fluidGridGutterWidth * (vars.columns-1))-(.5 / vars.gridRowWidth * 100 * 1%)"
    }

rule("    .row-fluid") {
      width: 100%;
      with(mixins) { clearfix() }
      [class*="span"] {
        with(mixins) { inputBlockLevel() }
        float: left;
        marginLeft = vars.fluidGridGutterWidth
        declarations[*margin-left] = "vars.fluidGridGutterWidth-(.5 / vars.gridRowWidth * 100 * 1%)"
      }
      [class*="span"]:first-child {
        marginLeft = 0.px
      }

      // Space grid-sized controls properly if multiple per line
      .controls-row [class*="span"] + [class*="span"] {
        marginLeft = vars.fluidGridGutterWidth
      }

      // generate .spanX and .offsetX
      .spanX (vars.gridColumns);
      .offsetX (vars.gridColumns);
    }

  }

  fun CssBuilder.input(vars.gridColumnWidth, vars.gridGutterWidth)

    .spanX (vars.index) when (vars.index > 0px) {
      input.span@{index}, textarea.span@{index}, .uneditable-input.span@{index} { .span(vars.index);
 }
      with(mixins) { spanX(vars.index-1) }
    }
    .spanX (0px) {}

    fun CssBuilder.span(vars.columns)
      width: ((vars.gridColumnWidth) * vars.columns) + (vars.gridGutterWidth * (vars.columns-1))-14;
    }

rule("    input textarea .uneditable-input") {
      marginLeft = 0.px // override margin-left from core grid system
    }

    // Space grid-sized controls properly if multiple per line
    .controls-row [class*="span"] + [class*="span"] {
      marginLeft = vars.gridGutterWidth
    }

    // generate .spanX
    .spanX (vars.gridColumns);

  }
}
    */}


    override fun CssBuilder.modals(){/*
// Background
rule(".modal-backdrop") {
  position = Position.fixed
  top = 0.px
  right = 0.px
  bottom = 0.px
  left = 0.px
  z-index: vars.zindexModalBackdrop;
  backgroundColor = vars.black
  // Fade for backdrop
  &.fade { opacity: 0px;
 }
}

rule(".modal-backdrop .modal-backdrop.fade.in") {
  with(mixins) { opacity(80) }
}

// Base modal
rule(".modal") {
  position = Position.fixed
  top: 10%;
  left: 50%;
  z-index: vars.zindexModal;
  width: 560px;
  marginLeft = -280.px
  backgroundColor = vars.white
  border = Border(1.px, BorderStyle.solid, Color(#999))
  border: 1px solid rgba(0,0,0,.3);
  declarations["*border"] = Border(1.px, BorderStyle.solid, Color(#999))
 /* IE6-7 */
  with(mixins) { borderRadius(6px) }
  with(mixins) { boxShadow(0px 3px 7px rgba(0,0,0,0.3)) }
  with(mixins) { backgroundClip(padding-box) }
  // Remove focus outline from opened modal
  outline: none;
rule("  &.fade") {
    with(mixins) { transition(e('opacity .3s linear, top .3s ease-out')) }
    top: -25%;
  }
  &.fade.in { top: 10%;
 }
}

rule(".modal-header") {
  padding = Padding(9.px, 15.px)
  borderBottom = Border(1.px, BorderStyle.solid, Color(solid))
  // Close icon
  .close { marginTop = 2.px }
  // Heading
  h3 {
    margin = Margin(0.px)
    line-height: 30px;
  }
}

// Body (where all modal content resides)
rule(".modal-body") {
  position = Position.relative
  overflow-y: auto;
  max-height: 400px;
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
  text-align: right;
 // right align buttons
  backgroundColor = Color("#f5f5f5")
  borderTop = Border(1.px, BorderStyle.solid, Color(solid))
  with(mixins) { borderRadius(0px 0px 6px 6px) }
  with(mixins) { boxShadow(inset 0px 1px 0px vars.white) }
  with(mixins) { clearfix() }
 // clear it in case folks use .pull-* classes on buttons

  // Properly space out buttons
  .btn + .btn {
    marginLeft = 5.px
    marginBottom = 0.px // account for input[type="submit"] which gets the bottom margin like all other inputs
  }
  // but override that for button groups
  .btn-group .btn + .btn {
    marginLeft = -1.px
  }
  // and override it for block buttons as well
  .btn-block + .btn-block {
    marginLeft = 0.px
  }
}
    */}


    override fun CssBuilder.navbar(){/*
// COMMON STYLES

// Base class and wrapper
rule(".navbar") {
  overflow: visible;
  marginBottom = vars.baseLineHeight

  // Fix for IE7's bad z-indexing so dropdowns don't appear below content that follows the navbar
  declarations[*position] = "relative"
  declarations[*z-index] = "2"
}

// Inner for background effects
// Gradient is applied to its own element because overflow visible is not honored by IE when filter is present
rule(".navbar-inner") {
  min-height: vars.navbarHeight;
  paddingLeft = 20.px
  paddingRight = 20.px
  #gradient > .vertical(vars.navbarBackgroundHighlight, vars.navbarBackground);
  border = Border(1.px, BorderStyle.solid, vars.navbarBorder)
  with(mixins) { borderRadius(vars.baseBorderRadius) }
  with(mixins) { boxShadow(0px 1px 4px rgba(0,0,0,.065)) }

  // Prevent floats from breaking the navbar
  with(mixins) { clearfix() }
}

// Set width to auto for default container
// We then reset it for fixed navbars in the #gridSystem mixin
rule(".navbar .container") {
  width: auto;
}

// Override the default collapsed state
rule(".nav-collapse.collapse") {
  height: auto;
  overflow: visible;
}


// Brand: website or project name
rule(".navbar .brand") {
  float: left;
  display = Display.block
  // Vertically center the text given vars.navbarHeight
  padding: ((vars.navbarHeight-vars.baseLineHeight) / 2) 20px ((vars.navbarHeight-vars.baseLineHeight) / 2);
  marginLeft = -20.px
 // negative indent to left-align the text down the page
  fontSize = 20.px
  font-weight: 200;
  color = vars.navbarBrandColor
  text-shadow: 0px 1px 0px vars.navbarBackgroundHighlight;
  &:hover &:focus {
    text-decoration: none;
  }
}

// Plain text in topbar
rule(".navbar-text") {
  marginBottom = 0.px
  lineHeight = vars.navbarHeight
  color = vars.navbarText
}

// Janky solution for now to account for links outside the .nav
rule(".navbar-link") {
  color = vars.navbarLinkColor
  &:hover &:focus {
    color = vars.navbarLinkColorHover
  }
}

// Dividers in navbar
rule(".navbar .divider-vertical") {
  height: vars.navbarHeight;
  margin = Margin(0.px, 9.px)
  borderLeft = Border(1.px, BorderStyle.solid, Color(solid))
  borderRight = Border(1.px, BorderStyle.solid, Color(solid))
}

// Buttons in navbar
rule(".navbar .btn .navbar .btn-group") {
  with(mixins) { navbarVerticalAlign(30px) }
 // Vertically center in navbar
}

rule(".navbar .btn-group .btn .navbar .input-prepend .btn .navbar .input-append .btn .navbar .input-prepend .btn-group .navbar .input-append .btn-group") {
  marginTop = 0.px // then undo the margin here so we don't accidentally double it
}

// Navbar forms
rule(".navbar-form") {
  marginBottom = 0.px // remove default bottom margin
  with(mixins) { clearfix() }
  input select .radio .checkbox {
    with(mixins) { navbarVerticalAlign(30px) }
 // Vertically center in navbar
  }
  input select .btn {
    display = Display.inlineBlock
    marginBottom = 0.px
  }
  input[type="image"] input[type="checkbox"] input[type="radio"] {
    marginTop = 3.px
  }
  .input-append .input-prepend {
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
  float: left;
  with(mixins) { navbarVerticalAlign(30px) }
 // Vertically center in navbar
  marginBottom = 0.px
  .search-query {
    marginBottom = 0.px
    padding = Padding(4.px, 14.px)
    #font > .sans-serif(13px, normal, 1);
    with(mixins) { borderRadius(15px) }
 // redeclare because of specificity of the type attribute
  }
}



// Static navbar
rule(".navbar-static-top") {
  position = Position.static
  marginBottom = 0.px // remove 18px margin for default navbar
  .navbar-inner {
    with(mixins) { borderRadius(0px) }
  }
}



// Fixed navbar

// Shared (top/bottom) styles
rule(".navbar-fixed-top .navbar-fixed-bottom") {
  position = Position.fixed
  right = 0.px
  left = 0.px
  z-index: vars.zindexFixedNavbar;
  marginBottom = 0.px // remove 18px margin for default navbar
}

rule(".navbar-fixed-top .navbar-inner .navbar-static-top .navbar-inner") {
  border-width: 0px 0px 1px;
}

rule(".navbar-fixed-bottom .navbar-inner") {
  border-width: 1px 0px 0px;
}

rule(".navbar-fixed-top .navbar-inner .navbar-fixed-bottom .navbar-inner") {
  paddingLeft = 0.px
  paddingRight = 0.px
  with(mixins) { borderRadius(0px) }
}

// Reset container width
// Required here as we reset the width earlier on and the grid mixins don't override early enough
rule(".navbar-static-top .container .navbar-fixed-top .container .navbar-fixed-bottom .container") {
  #grid > .core > .span(vars.gridColumns);
}

// Fixed to top
rule(".navbar-fixed-top") {
  top = 0.px
}

rule(".navbar-fixed-top .navbar-static-top") {
  .navbar-inner {
    with(mixins) { boxShadow(~"0px 1px 10px rgba(0,0,0,.1)") }
  }
}

// Fixed to bottom
rule(".navbar-fixed-bottom") {
  bottom = 0.px
  .navbar-inner {
    with(mixins) { boxShadow(~"0px -1px 10px rgba(0,0,0,.1)") }
  }
}



// NAVIGATION
rule(".navbar .nav") {
  position = Position.relative
  left = 0.px
  display = Display.block
  float: left;
  margin = Margin(0.px, 10.px, 0.px, 0.px)
}

rule(".navbar .nav.pull-right") {
  float: right;
 // redeclare due to specificity
  marginRight = 0.px // remove margin on float right nav
}

rule(".navbar .nav > li") {
  float: left;
}

// Links
rule(".navbar .nav > li > a") {
  float: none;
  // Vertically center the text given vars.navbarHeight
  padding: ((vars.navbarHeight-vars.baseLineHeight) / 2) 15px ((vars.navbarHeight-vars.baseLineHeight) / 2);
  color = vars.navbarLinkColor
  text-decoration: none;
  text-shadow: 0px 1px 0px vars.navbarBackgroundHighlight;
}

rule(".navbar .nav .dropdown-toggle .caret") {
  marginTop = 8.px
}

// Hover/focus
rule(".navbar .nav > li > a:focus .navbar .nav > li > a:hover") {
  backgroundColor = vars.navbarLinkBackgroundHover
 // "transparent" is default to differentiate :hover/:focus from .active
  color = vars.navbarLinkColorHover
  text-decoration: none;
}

// Active nav items
rule(".navbar .nav > .active > a .navbar .nav > .active > a:hover .navbar .nav > .active > a:focus") {
  color = vars.navbarLinkColorActive
  text-decoration: none;
  backgroundColor = vars.navbarLinkBackgroundActive
  with(mixins) { boxShadow(inset 0px 3px 8px rgba(0,0,0,.125)) }
}

// Navbar button for toggling navbar items in responsive layouts
// These definitions need to come after '.navbar .btn'
rule(".navbar .btn-navbar") {
  display = Display.none
  float: right;
  padding = Padding(7.px, 10.px)
  marginLeft = 5.px
  marginRight = 5.px
  with(mixins) { buttonBackground(darken(vars.navbarBackgroundHighlight, 5%), darken(vars.navbarBackground, 5%)) }
  with(mixins) { boxShadow(~"inset 0px 1px 0px rgba(255,255,255,.1), 0px 1px 0px rgba(255,255,255,.075)") }
}

rule(".navbar .btn-navbar .icon-bar") {
  display = Display.block
  width: 18px;
  height: 2px;
  backgroundColor = Color("#f5f5f5")
  with(mixins) { borderRadius(1px) }
  with(mixins) { boxShadow(0px 1px 0px rgba(0,0,0,.25)) }
}

rule(".btn-navbar .icon-bar + .icon-bar") {
  marginTop = 3.px
}



// Dropdown menus

// Menu position and menu carets
rule(".navbar .nav > li > .dropdown-menu") {
  &:before {
    content: '';
    display = Display.inlineBlock
    border-left:   7px solid transparent;
    border-right:  7px solid transparent;
    borderBottom = Border(7.px, BorderStyle.solid, Color(solid))
    border-bottom-color = vars.dropdownBorder
    position = Position.absolute
    top = -7.px
    left = 9.px
  }
  &:after {
    content: '';
    display = Display.inlineBlock
    border-left:   6px solid transparent;
    border-right:  6px solid transparent;
    borderBottom = Border(6.px, BorderStyle.solid, Color(solid))
    position = Position.absolute
    top = -6.px
    left = 10.px
  }
}
// Menu position and menu caret support for dropups via extra dropup class
rule(".navbar-fixed-bottom .nav > li > .dropdown-menu") {
  &:before {
    borderTop = Border(7.px, BorderStyle.solid, Color(solid))
    border-top-color = vars.dropdownBorder
    borderBottom = Border(0.px)
    bottom = -7.px
    top: auto;
  }
  &:after {
    borderTop = Border(6.px, BorderStyle.solid, Color(solid))
    borderBottom = Border(0.px)
    bottom = -6.px
    top: auto;
  }
}

// Caret should match text color on hover/focus
rule(".navbar .nav li.dropdown > a:hover .caret .navbar .nav li.dropdown > a:focus .caret") {
  border-top-color = vars.navbarLinkColorHover
  border-bottom-color = vars.navbarLinkColorHover
}

// Remove background color from open dropdown
rule(".navbar .nav li.dropdown.open > .dropdown-toggle .navbar .nav li.dropdown.active > .dropdown-toggle .navbar .nav li.dropdown.open.active > .dropdown-toggle") {
  backgroundColor = vars.navbarLinkBackgroundActive
  color = vars.navbarLinkColorActive
}

rule(".navbar .nav li.dropdown > .dropdown-toggle .caret") {
  border-top-color = vars.navbarLinkColor
  border-bottom-color = vars.navbarLinkColor
}

rule(".navbar .nav li.dropdown.open > .dropdown-toggle .caret .navbar .nav li.dropdown.active > .dropdown-toggle .caret .navbar .nav li.dropdown.open.active > .dropdown-toggle .caret") {
  border-top-color = vars.navbarLinkColorActive
  border-bottom-color = vars.navbarLinkColorActive
}

// Right aligned menus need alt position
rule(".navbar .pull-right > li > .dropdown-menu .navbar .nav > li > .dropdown-menu.pull-right") {
  left: auto;
  right = 0.px
  &:before {
    left: auto;
    right = 12.px
  }
  &:after {
    left: auto;
    right = 13.px
  }
  .dropdown-menu {
    left: auto;
    right: 100%;
    marginLeft = 0.px
    marginRight = -1.px
    with(mixins) { borderRadius(6px 0px 6px 6px) }
  }
}


// Inverted navbar
rule(".navbar-inverse") {
rule("  .navbar-inner") {
    #gradient > .vertical(vars.navbarInverseBackgroundHighlight, vars.navbarInverseBackground);
    borderColor =  vars.navbarInverseBorder
  }

rule("  .brand .nav > li > a") {
    color = vars.navbarInverseLinkColor
    text-shadow: 0px -1px 0px rgba(0,0,0,.25);
    &:hover &:focus {
      color = vars.navbarInverseLinkColorHover
    }
  }

rule("  .brand") {
    color = vars.navbarInverseBrandColor
  }

rule("  .navbar-text") {
    color = vars.navbarInverseText
  }

rule("  .nav > li > a:focus .nav > li > a:hover") {
    backgroundColor = vars.navbarInverseLinkBackgroundHover
    color = vars.navbarInverseLinkColorHover
  }

rule("  .nav .active > a .nav .active > a:hover .nav .active > a:focus") {
    color = vars.navbarInverseLinkColorActive
    backgroundColor = vars.navbarInverseLinkBackgroundActive
  }

  // Inline text links
  .navbar-link {
    color = vars.navbarInverseLinkColor
    &:hover &:focus {
      color = vars.navbarInverseLinkColorHover
    }
  }

  // Dividers in navbar
  .divider-vertical {
    border-left-color = vars.navbarInverseBackground
    border-right-color = vars.navbarInverseBackgroundHighlight
  }

  // Dropdowns
  .nav li.dropdown.open > .dropdown-toggle .nav li.dropdown.active > .dropdown-toggle .nav li.dropdown.open.active > .dropdown-toggle {
    backgroundColor = vars.navbarInverseLinkBackgroundActive
    color = vars.navbarInverseLinkColorActive
  }
  .nav li.dropdown > a:hover .caret .nav li.dropdown > a:focus .caret {
    border-top-color = vars.navbarInverseLinkColorActive
    border-bottom-color = vars.navbarInverseLinkColorActive
  }
  .nav li.dropdown > .dropdown-toggle .caret {
    border-top-color = vars.navbarInverseLinkColor
    border-bottom-color = vars.navbarInverseLinkColor
  }
  .nav li.dropdown.open > .dropdown-toggle .caret .nav li.dropdown.active > .dropdown-toggle .caret .nav li.dropdown.open.active > .dropdown-toggle .caret {
    border-top-color = vars.navbarInverseLinkColorActive
    border-bottom-color = vars.navbarInverseLinkColorActive
  }

  // Navbar search
  .navbar-search {
    .search-query {
      color = vars.white
      backgroundColor = vars.navbarInverseSearchBackground
      borderColor =  vars.navbarInverseSearchBorder
      with(mixins) { boxShadow(~"inset 0px 1px 2px rgba(0,0,0,.1), 0px 1px 0px rgba(255,255,255,.15)") }
      with(mixins) { transition(none) }
      with(mixins) { placeholder(vars.navbarInverseSearchPlaceholderColor) }

      // Focus states (we use .focused since IE7-8 and down doesn't support :focus)
      &:focus &.focused {
        padding = Padding(5.px, 15.px)
        color = vars.grayDark
        text-shadow: 0px 1px 0px vars.white;
        backgroundColor = vars.navbarInverseSearchBackgroundFocus
        border: 0px;
        with(mixins) { boxShadow(0px 0px 3px rgba(0,0,0,.15)) }
        outlineWidth = 0.px
      }
    }
  }

  // Navbar collapse button
  .btn-navbar {
    with(mixins) { buttonBackground(darken(vars.navbarInverseBackgroundHighlight, 5%), darken(vars.navbarInverseBackground, 5%)) }
  }

}
    */}


    override fun CssBuilder.navs(){/*
// BASE CLASS
rule(".nav") {
  marginLeft = 0.px
  marginBottom = vars.baseLineHeight
  list-style: none;
}

// Make links block level
rule(".nav > li > a") {
  display = Display.block
}

rule(".nav > li > a:hover .nav > li > a:focus") {
  text-decoration: none;
  backgroundColor = vars.grayLighter
}

// Prevent IE8 from misplacing imgs
// See https://github.com/h5bp/html5-boilerplate/issues/984#issuecomment-3985989
rule(".nav > li > a > img") {
  max-width: none;
}

// Redeclare pull classes because of specifity
rule(".nav > .pull-right") {
  float: right;
}

// Nav headers (for dropdowns and lists)
rule(".nav-header") {
  display = Display.block
  padding = Padding(3.px, 15.px)
  fontSize = 11.px
  font-weight: bold;
  lineHeight = vars.baseLineHeight
  color = vars.grayLight
  text-shadow: 0px 1px 0px rgba(255,255,255,.5);
  text-transform: uppercase;
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

rule(".nav-list > li > a .nav-list .nav-header") {
  marginLeft = -15.px
  marginRight = -15.px
  text-shadow: 0px 1px 0px rgba(255,255,255,.5);
}

rule(".nav-list > li > a") {
  padding = Padding(3.px, 15.px)
}

rule(".nav-list > .active > a .nav-list > .active > a:hover .nav-list > .active > a:focus") {
  color = vars.white
  text-shadow: 0px -1px 0px rgba(0,0,0,.2);
  backgroundColor = vars.linkColor
}

rule(".nav-list [class^="icon-"] .nav-list [class*=" icon-"]") {
  marginRight = 2.px
}
// Dividers (basically an hr) within the dropdown
rule(".nav-list .divider") {
  with(mixins) { navDivider() }
}



// TABS AND PILLS

// Common styles
rule(".nav-tabs .nav-pills") {
  with(mixins) { clearfix() }
}

rule(".nav-tabs > li .nav-pills > li") {
  float: left;
}

rule(".nav-tabs > li > a .nav-pills > li > a") {
  paddingRight = 12.px
  paddingLeft = 12.px
  marginRight = 2.px
  line-height: 14px;
 // keeps the overall height an even number
}

// TABS
// ----

// Give the tabs something to sit on
rule(".nav-tabs") {
  borderBottom = Border(1.px, BorderStyle.solid, Color(solid))
}
// Make the list-items overlay the bottom border
rule(".nav-tabs > li") {
  marginBottom = -1.px
}
// Actual tabs (as links)
rule(".nav-tabs > li > a") {
  paddingTop = 8.px
  paddingBottom = 8.px
  lineHeight = vars.baseLineHeight
  border = Border(1.px, BorderStyle.solid, Color(transparent))
  with(mixins) { borderRadius(4px 4px 0px 0px) }
  &:hover &:focus {
    border-color: vars.grayLighter vars.grayLighter #ddd;
  }
}
// Active state, and it's :hover/:focus to override normal :hover/:focus
rule(".nav-tabs > .active > a .nav-tabs > .active > a:hover .nav-tabs > .active > a:focus") {
  color = vars.gray
  backgroundColor = vars.bodyBackground
  border = Border(1.px, BorderStyle.solid, Color(#ddd))
  border-bottom-color: transparent;
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
  with(mixins) { borderRadius(5px) }
}

// Active state
rule(".nav-pills > .active > a .nav-pills > .active > a:hover .nav-pills > .active > a:focus") {
  color = vars.white
  backgroundColor = vars.linkColor
}



// STACKED NAV

// Stacked tabs and pills
rule(".nav-stacked > li") {
  float: none;
}

rule(".nav-stacked > li > a") {
  marginRight = 0.px // no need for the gap between nav items
}

// Tabs
rule(".nav-tabs.nav-stacked") {
  borderBottom = Border(0.px)
}

rule(".nav-tabs.nav-stacked > li > a") {
  border = Border(1.px, BorderStyle.solid, Color(#ddd))
  with(mixins) { borderRadius(0px) }
}

rule(".nav-tabs.nav-stacked > li:first-child > a") {
  with(mixins) { borderTopRadius(4px) }
}

rule(".nav-tabs.nav-stacked > li:last-child > a") {
  with(mixins) { borderBottomRadius(4px) }
}

rule(".nav-tabs.nav-stacked > li > a:hover .nav-tabs.nav-stacked > li > a:focus") {
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
  with(mixins) { borderRadius(0px 0px 6px 6px) }
 // remove the top rounded corners here since there is a hard edge above the menu
}

rule(".nav-pills .dropdown-menu") {
  with(mixins) { borderRadius(6px) }
 // make rounded corners match the pills
}

// Default dropdown links
// Make carets use linkColor to start
rule(".nav .dropdown-toggle .caret") {
  border-top-color = vars.linkColor
  border-bottom-color = vars.linkColor
  marginTop = 6.px
}

rule(".nav .dropdown-toggle:hover .caret .nav .dropdown-toggle:focus .caret") {
  border-top-color = vars.linkColorHover
  border-bottom-color = vars.linkColorHover
}
/* move down carets for tabs */
rule(".nav-tabs .dropdown-toggle .caret") {
  marginTop = 8.px
}

// Active dropdown links
rule(".nav .active .dropdown-toggle .caret") {
  border-topColor = Color("#fff")
  border-bottomColor = Color("#fff")
}

rule(".nav-tabs .active .dropdown-toggle .caret") {
  border-top-color = vars.gray
  border-bottom-color = vars.gray
}

// Active:hover/:focus dropdown links
rule(".nav > .dropdown.active > a:hover .nav > .dropdown.active > a:focus") {
  cursor = Cursor.pointer
}

// Open dropdowns
rule(".nav-tabs .open .dropdown-toggle .nav-pills .open .dropdown-toggle .nav > li.dropdown.open.active > a:hover .nav > li.dropdown.open.active > a:focus") {
  color = vars.white
  backgroundColor = vars.grayLight
  borderColor =  vars.grayLight
}

rule(".nav li.dropdown.open .caret .nav li.dropdown.open.active .caret .nav li.dropdown.open a:hover .caret .nav li.dropdown.open a:focus .caret") {
  border-top-color = vars.white
  border-bottom-color = vars.white
  with(mixins) { opacity(100) }
}

// Dropdowns in stacked tabs
rule(".tabs-stacked .open > a:hover .tabs-stacked .open > a:focus") {
  borderColor =  vars.grayLight
}



// TABBABLE
// --------


// COMMON STYLES

// Clear any floats
rule(".tabbable") {
  with(mixins) { clearfix() }
}

rule(".tab-content") {
  overflow: auto;
 // prevent content from running below tabs
}

// Remove border on bottom, left, right
rule(".tabs-below > .nav-tabs .tabs-right > .nav-tabs .tabs-left > .nav-tabs") {
  borderBottom = Border(0.px)
}

// Show/hide tabbable areas
rule(".tab-content > .tab-pane .pill-content > .pill-pane") {
  display = Display.none
}

rule(".tab-content > .active .pill-content > .active") {
  display = Display.block
}


// BOTTOM
// ------
rule(".tabs-below > .nav-tabs") {
  borderTop = Border(1.px, BorderStyle.solid, Color(solid))
}

rule(".tabs-below > .nav-tabs > li") {
  marginTop = -1.px
  marginBottom = 0.px
}

rule(".tabs-below > .nav-tabs > li > a") {
  with(mixins) { borderRadius(0px 0px 4px 4px) }
  &:hover &:focus {
    border-bottom-color: transparent;
    border-topColor = Color("#ddd")
  }
}

rule(".tabs-below > .nav-tabs > .active > a .tabs-below > .nav-tabs > .active > a:hover .tabs-below > .nav-tabs > .active > a:focus") {
  border-color: transparent #ddd #ddd #ddd;
}

// LEFT & RIGHT

// Common styles
rule(".tabs-left > .nav-tabs > li .tabs-right > .nav-tabs > li") {
  float: none;
}

rule(".tabs-left > .nav-tabs > li > a .tabs-right > .nav-tabs > li > a") {
  min-width: 74px;
  marginRight = 0.px
  marginBottom = 3.px
}

// Tabs on the left
rule(".tabs-left > .nav-tabs") {
  float: left;
  marginRight = 19.px
  borderRight = Border(1.px, BorderStyle.solid, Color(solid))
}

rule(".tabs-left > .nav-tabs > li > a") {
  marginRight = -1.px
  with(mixins) { borderRadius(4px 0px 0px 4px) }
}

rule(".tabs-left > .nav-tabs > li > a:hover .tabs-left > .nav-tabs > li > a:focus") {
  border-color: vars.grayLighter #ddd vars.grayLighter vars.grayLighter;
}

rule(".tabs-left > .nav-tabs .active > a .tabs-left > .nav-tabs .active > a:hover .tabs-left > .nav-tabs .active > a:focus") {
  border-color: #ddd transparent #ddd #ddd;
  declarations["*border-right-color"] = vars.white
}

// Tabs on the right
rule(".tabs-right > .nav-tabs") {
  float: right;
  marginLeft = 19.px
  borderLeft = Border(1.px, BorderStyle.solid, Color(solid))
}

rule(".tabs-right > .nav-tabs > li > a") {
  marginLeft = -1.px
  with(mixins) { borderRadius(0px 4px 4px 0px) }
}

rule(".tabs-right > .nav-tabs > li > a:hover .tabs-right > .nav-tabs > li > a:focus") {
  border-color: vars.grayLighter vars.grayLighter vars.grayLighter #ddd;
}

rule(".tabs-right > .nav-tabs .active > a .tabs-right > .nav-tabs .active > a:hover .tabs-right > .nav-tabs .active > a:focus") {
  border-color: #ddd #ddd #ddd transparent;
  declarations["*border-left-color"] = vars.white
}



// DISABLED STATES

// Gray out text
rule(".nav > .disabled > a") {
  color = vars.grayLight
}
// Nuke hover/focus effects
rule(".nav > .disabled > a:hover .nav > .disabled > a:focus") {
  text-decoration: none;
  background-color: transparent;
  cursor = Cursor.default
}
    */}


    override fun CssBuilder.pager(){/*
rule(".pager") {
  margin: vars.baseLineHeight 0px;
  list-style: none;
  text-align: center;
  with(mixins) { clearfix() }
}

rule(".pager li") {
  display = Display.inline
}

rule(".pager li > a .pager li > span") {
  display = Display.inlineBlock
  padding = Padding(5.px, 14.px)
  backgroundColor = Color("#fff")
  border = Border(1.px, BorderStyle.solid, Color(#ddd))
  with(mixins) { borderRadius(15px) }
}

rule(".pager li > a:hover .pager li > a:focus") {
  text-decoration: none;
  backgroundColor = Color("#f5f5f5")
}

rule(".pager .next > a .pager .next > span") {
  float: right;
}

rule(".pager .previous > a .pager .previous > span") {
  float: left;
}

rule(".pager .disabled > a .pager .disabled > a:hover .pager .disabled > a:focus .pager .disabled > span") {
  color = vars.grayLight
  backgroundColor = Color("#fff")
  cursor = Cursor.default
}
    */}


    override fun CssBuilder.pagination(){/*
// Space out pagination from surrounding content
rule(".pagination") {
  margin: vars.baseLineHeight 0px;
}

rule(".pagination ul") {
  // Allow for text-based alignment
  display = Display.inlineBlock
  with(mixins) { ie7InlineBlock() }
  // Reset default ul styles
  marginLeft = 0.px
  marginBottom = 0.px
  // Visuals
  with(mixins) { borderRadius(vars.baseBorderRadius) }
  with(mixins) { boxShadow(0px 1px 2px rgba(0,0,0,.05)) }
}

rule(".pagination ul > li") {
  display = Display.inline // Remove list-style and block-level defaults
}

rule(".pagination ul > li > a .pagination ul > li > span") {
  float: left;
 // Collapse white-space
  padding = Padding(4.px, 12.px)
  lineHeight = vars.baseLineHeight
  text-decoration: none;
  backgroundColor = vars.paginationBackground
  border = Border(1.px, BorderStyle.solid, vars.paginationBorder)
  border-left-width: 0px;
}

rule(".pagination ul > li > a:hover .pagination ul > li > a:focus .pagination ul > .active > a .pagination ul > .active > span") {
  backgroundColor = vars.paginationActiveBackground
}

rule(".pagination ul > .active > a .pagination ul > .active > span") {
  color = vars.grayLight
  cursor = Cursor.default
}

rule(".pagination ul > .disabled > span .pagination ul > .disabled > a .pagination ul > .disabled > a:hover .pagination ul > .disabled > a:focus") {
  color = vars.grayLight
  background-color: transparent;
  cursor = Cursor.default
}

rule(".pagination ul > li:first-child > a .pagination ul > li:first-child > span") {
  border-left-width: 1px;
  with(mixins) { borderLeftRadius(vars.baseBorderRadius) }
}

rule(".pagination ul > li:last-child > a .pagination ul > li:last-child > span") {
  with(mixins) { borderRightRadius(vars.baseBorderRadius) }
}


// Alignment
rule(".pagination-centered") {
  text-align: center;
}

rule(".pagination-right") {
  text-align: right;
}


// Sizing

// Large
rule(".pagination-large") {
  ul > li > a ul > li > span {
    padding: vars.paddingLarge;
    fontSize = vars.fontSizeLarge
  }
  ul > li:first-child > a ul > li:first-child > span {
    with(mixins) { borderLeftRadius(vars.borderRadiusLarge) }
  }
  ul > li:last-child > a ul > li:last-child > span {
    with(mixins) { borderRightRadius(vars.borderRadiusLarge) }
  }
}

// Small and mini
rule(".pagination-mini .pagination-small") {
  ul > li:first-child > a ul > li:first-child > span {
    with(mixins) { borderLeftRadius(vars.borderRadiusSmall) }
  }
  ul > li:last-child > a ul > li:last-child > span {
    with(mixins) { borderRightRadius(vars.borderRadiusSmall) }
  }
}

// Small
rule(".pagination-small") {
  ul > li > a ul > li > span {
    padding: vars.paddingSmall;
    fontSize = vars.fontSizeSmall
  }
}
// Mini
rule(".pagination-mini") {
  ul > li > a ul > li > span {
    padding: vars.paddingMini;
    fontSize = vars.fontSizeMini
  }
}
    */}


    override fun CssBuilder.popovers(){/*
rule(".popover") {
  position = Position.absolute
  top = 0.px
  left = 0.px
  z-index: vars.zindexPopover;
  display = Display.none
  max-width: 276px;
  padding = Padding(1.px)
  text-align: left;
 // Reset given new insertion method
  backgroundColor = vars.popoverBackground
  -webkit-background-clip: padding-box;
     -moz-background-clip: padding;
          background-clip: padding-box;
  border = Border(1.px, BorderStyle.solid, Color(#ccc))
  border: 1px solid rgba(0,0,0,.2);
  with(mixins) { borderRadius(6px) }
  with(mixins) { boxShadow(0px 5px 10px rgba(0,0,0,.2)) }

  // Overrides for proper insertion
  whiteSpace = WhiteSpace.normal

  // Offset the popover to account for the popover arrow
  &.top     { marginTop = -10.px
 }
  &.right   { marginLeft = 10.px }
  &.bottom  { marginTop = 10.px }
  &.left    { marginLeft = -10.px
 }
}

rule(".popover-title") {
  margin = Margin(0.px) // reset heading margin
  padding = Padding(8.px, 14.px)
  fontSize = 14.px
  font-weight: normal;
  line-height: 18px;
  backgroundColor = vars.popoverTitleBackground
  border-bottom: 1px solid darken(vars.popoverTitleBackground, 5%);
  with(mixins) { borderRadius(5px 5px 0px 0px) }
rule("  &:empty") {
    display = Display.none
  }
}

rule(".popover-content") {
  padding = Padding(9.px, 14.px)
}

// Arrows
//
// .arrow is outer, .arrow:after is inner
rule(".popover .arrow .popover .arrow:after") {
  position = Position.absolute
  display = Display.block
  width: 0px;
  height: 0px;
  border-color: transparent;
  border-style: solid;
}

rule(".popover .arrow") {
  border-width: vars.popoverArrowOuterWidth;
}

rule(".popover .arrow:after") {
  border-width: vars.popoverArrowWidth;
  content: "";
}

rule(".popover") {
  &.top .arrow {
    left: 50%;
    marginLeft = -vars.popoverArrowOuterWidth
    border-bottom-width: 0px;
    border-topColor = Color("#999")
 // IE8 fallback
    border-top-color = vars.popoverArrowOuterColor
    bottom: -vars.popoverArrowOuterWidth;
    &:after {
      bottom = 1.px
      marginLeft = -vars.popoverArrowWidth
      border-bottom-width: 0px;
      border-top-color = vars.popoverArrowColor
    }
  }
  &.right .arrow {
    top: 50%;
    left: -vars.popoverArrowOuterWidth;
    marginTop = -vars.popoverArrowOuterWidth
    border-left-width: 0px;
    border-rightColor = Color("#999")
 // IE8 fallback
    border-right-color = vars.popoverArrowOuterColor
    &:after {
      left = 1.px
      bottom: -vars.popoverArrowWidth;
      border-left-width: 0px;
      border-right-color = vars.popoverArrowColor
    }
  }
  &.bottom .arrow {
    left: 50%;
    marginLeft = -vars.popoverArrowOuterWidth
    border-top-width: 0px;
    border-bottomColor = Color("#999")
 // IE8 fallback
    border-bottom-color = vars.popoverArrowOuterColor
    top: -vars.popoverArrowOuterWidth;
    &:after {
      top = 1.px
      marginLeft = -vars.popoverArrowWidth
      border-top-width: 0px;
      border-bottom-color = vars.popoverArrowColor
    }
  }

rule("  &.left .arrow") {
    top: 50%;
    right: -vars.popoverArrowOuterWidth;
    marginTop = -vars.popoverArrowOuterWidth
    border-right-width: 0px;
    border-leftColor = Color("#999")
 // IE8 fallback
    border-left-color = vars.popoverArrowOuterColor
    &:after {
      right = 1.px
      border-right-width: 0px;
      border-left-color = vars.popoverArrowColor
      bottom: -vars.popoverArrowWidth;
    }
  }

}
    */}


    override fun CssBuilder.progressBars(){/*
// ANIMATIONS

// Webkit
rule("VAR-webkit-keyframes progress-bar-stripes") {
  from  { background-position: 40px 0px;
 }
  to    { background-position: 0px 0px;
 }
}

// Firefox
rule("VAR-moz-keyframes progress-bar-stripes") {
  from  { background-position: 40px 0px;
 }
  to    { background-position: 0px 0px;
 }
}

// IE9
rule("VAR-ms-keyframes progress-bar-stripes") {
  from  { background-position: 40px 0px;
 }
  to    { background-position: 0px 0px;
 }
}

// Opera
rule("VAR-o-keyframes progress-bar-stripes") {
  from  { background-position: 0px 0px;
 }
  to    { background-position: 40px 0px;
 }
}

// Spec
rule("vars.keyframes progress-bar-stripes") {
  from  { background-position: 40px 0px;
 }
  to    { background-position: 0px 0px;
 }
}



// THE BARS
// --------

// Outer container
rule(".progress") {
  overflow: hidden;
  height: vars.baseLineHeight;
  marginBottom = vars.baseLineHeight
  #gradient > .vertical(#f5f5f5, #f9f9f9);
  with(mixins) { boxShadow(inset 0px 1px 2px rgba(0,0,0,.1)) }
  with(mixins) { borderRadius(vars.baseBorderRadius) }
}

// Bar of progress
rule(".progress .bar") {
  width: 0%;
  height: 100%;
  color = vars.white
  float: left;
  fontSize = 12.px
  text-align: center;
  text-shadow: 0px -1px 0px rgba(0,0,0,.25);
  #gradient > .vertical(#149bdf, #0480be);
  with(mixins) { boxShadow(inset 0px -1px 0px rgba(0,0,0,.15)) }
  with(mixins) { boxSizing(border-box) }
  with(mixins) { transition(width .6s ease) }
}

rule(".progress .bar + .bar") {
  with(mixins) { boxShadow(~"inset 1px 0px 0px rgba(0,0,0,.15), inset 0px -1px 0px rgba(0,0,0,.15)") }
}

// Striped bars
rule(".progress-striped .bar") {
  #gradient > .striped(#149bdf);
  with(mixins) { backgroundSize(40px 40px) }
}

// Call animation for the active one
rule(".progress.active .bar") {
  -webkit-animation: progress-bar-stripes 2s linear infinite;
     -moz-animation: progress-bar-stripes 2s linear infinite;
      -ms-animation: progress-bar-stripes 2s linear infinite;
       -o-animation: progress-bar-stripes 2s linear infinite;
          animation: progress-bar-stripes 2s linear infinite;
}



// COLORS
// ------

// Danger (red)
rule(".progress-danger .bar, .progress .bar-danger") {
  #gradient > .vertical(#ee5f5b, #c43c35);
}

rule(".progress-danger.progress-striped .bar, .progress-striped .bar-danger") {
  #gradient > .striped(#ee5f5b);
}

// Success (green)
rule(".progress-success .bar, .progress .bar-success") {
  #gradient > .vertical(#62c462, #57a957);
}

rule(".progress-success.progress-striped .bar, .progress-striped .bar-success") {
  #gradient > .striped(#62c462);
}

// Info (teal)
rule(".progress-info .bar, .progress .bar-info") {
  #gradient > .vertical(#5bc0de, #339bb9);
}

rule(".progress-info.progress-striped .bar, .progress-striped .bar-info") {
  #gradient > .striped(#5bc0de);
}

// Warning (orange)
rule(".progress-warning .bar, .progress .bar-warning") {
  #gradient > .vertical(lighten(vars.orange, 15%), vars.orange);
}

rule(".progress-warning.progress-striped .bar, .progress-striped .bar-warning") {
  #gradient > .striped(lighten(vars.orange, 15%));
}
    */}


    override fun CssBuilder.reset(){/*
// Display in IE6-9 and FF3
rule("article aside details figcaption figure footer header hgroup nav section") {
  display = Display.block
}

// Display block in IE6-9 and FF3
rule("audio canvas video") {
  display = Display.inlineBlock
  declarations["*display"] = Display.inline
  declarations[*zoom] = "1"
}

// Prevents modern browsers from displaying 'audio' without controls

audio:not([controls]) {
    display = Display.none
}

// Base settings
rule("html") {
  fontSize = 100.pct
  -webkit-text-size-adjust: 100%;
      -ms-text-size-adjust: 100%;
}
// Focus states
rule("a:focus") {
  with(mixins) { tabFocus() }
}
// Hover & Active
rule("a:hover a:active") {
  outlineWidth = 0.px
}

// Prevents sub and sup affecting line-height in all browsers
rule("sub sup") {
  position = Position.relative
  fontSize = 75.pct
  line-height: 0px;
  verticalAlign = VerticalAlign.baseline
}

rule("sup") {
  top: -0.5em;
}

rule("sub") {
  bottom: -0.25em;
}

// Img border in a's and image quality
rule("img") {
  /* Responsive images (ensure images don't scale beyond their parents) */
  max-width: 100%;
 /* Part 1: Set a maxium relative to the parent */
  width: auto\9;
 /* IE7-8 need help adjusting responsive images */
  height: auto;
 /* Part 2: Scale the height according to the width, otherwise you get stretching */

  verticalAlign = VerticalAlign.middle
  border: 0px;
  -ms-interpolation-mode: bicubic;
}

// Prevent max-width from affecting Google Maps
rule("#map_canvas img .google-maps img") {
  max-width: none;
}

// Forms

// Font size in all browsers, margin changes, misc consistency
rule("button input select textarea") {
  margin = Margin(0.px)
  fontSize = 100.pct
  verticalAlign = VerticalAlign.middle
}

rule("button input") {
  declarations[*overflow] = "visible"
 // Inner spacing ie IE6/7
  line-height: normal;
 // FF3/4 have !important on line-height in UA stylesheet
}

rule("button::-moz-focus-inner input::-moz-focus-inner") { // Inner padding and border oddities in FF3/4
  padding = Padding(0.px)
  border: 0px;
}
button html input[type="button"], // Avoid the WebKit bug in Android 4.0.* where (2) destroys native `audio` and `video` controls.
rule("input[type="reset"] input[type="submit"]") {
    -webkit-appearance: button;
 // Corrects inability to style clickable `input` types in iOS.
    cursor = Cursor.pointer // Improves usability and consistency of cursor style between image-type `input` and others.
}

rule("label select button input[type="button"] input[type="reset"] input[type="submit"] input[type="radio"] input[type="checkbox"]") {
    cursor = Cursor.pointer // Improves usability and consistency of cursor style between image-type `input` and others.
}

rule("input[type="search"]") { // Appearance in Safari/Chrome
  with(mixins) { boxSizing(content-box) }
  -webkit-appearance: textfield;
}

rule("input[type="search"]::-webkit-search-decoration input[type="search"]::-webkit-search-cancel-button") {
  -webkit-appearance: none;
 // Inner-padding issues in Chrome OSX, Safari 5
}

rule("textarea") {
  overflow: auto;
 // Remove vertical scrollbar in IE6-9
  verticalAlign = VerticalAlign.top
 // Readability and alignment cross-browser
}


// Printing
// Source: https://github.com/h5bp/html5-boilerplate/blob/master/css/main.css
rule("vars.media print") {
rule("  *") {
    text-shadow: none !important;
    color: #000 !important;
 // Black prints faster: h5bp.com/s
    background: transparent !important;
    box-shadow: none !important;
  }

rule("  a a:visited") {
    text-decoration: underline;
  }

rule("  a[href]:after") {
    content: " (" attr(href) ")";
  }

rule("  abbr[title]:after") {
    content: " (" attr(title) ")";
  }

  // Don't show links for images, or javascript/internal links
  .ir a:after a[href^="javascript:"]:after a[href^="#"]:after {
    content: "";
  }

rule("  pre blockquote") {
    border = Border(1.px, BorderStyle.solid, Color(#999))
    page-break-inside: avoid;
  }

rule("  thead") {
    display: table-header-group;
 // h5bp.com/t
  }

rule("  tr img") {
    page-break-inside: avoid;
  }

rule("  img") {
    max-width: 100% !important;
  }

rule("  vars.page") {
    margin: 0.5cm;
  }

rule("  p h2 h3") {
    orphans: 3;
    widows: 3;
  }

rule("  h2 h3") {
    page-break-after: avoid;
  }
}
    */}


    override fun CssBuilder.responsive1200pxMin(){/*
vars.media (min-width: 1200px) {

  // Fixed grid
  #grid > .core(vars.gridColumnWidth1200, vars.gridGutterWidth1200);

  // Fluid grid
  #grid > .fluid(vars.fluidGridColumnWidth1200, vars.fluidGridGutterWidth1200);

  // Input grid
  #grid > .input(vars.gridColumnWidth1200, vars.gridGutterWidth1200);

  // Thumbnails
  .thumbnails {
    marginLeft = -vars.gridGutterWidth1200
  }
  .thumbnails > li {
    marginLeft = vars.gridGutterWidth1200
  }
  .row-fluid .thumbnails {
    marginLeft = 0.px
  }

}
    */}


    override fun CssBuilder.responsive767pxMax(){/*
vars.media (max-width: 767px) {

  // Padding to set content in a bit
  body {
    paddingLeft = 20.px
    paddingRight = 20.px
  }
  // Negative indent the now static "fixed" navbar
  .navbar-fixed-top .navbar-fixed-bottom .navbar-static-top {
    marginLeft = -20.px
    marginRight = -20.px
  }
  // Remove padding on container given explicit padding set on body
  .container-fluid {
    padding = Padding(0.px)
  }

  // TYPOGRAPHY
  // ----------
  // Reset horizontal dl
  .dl-horizontal {
    dt {
      float: none;
      clear: none;
      width: auto;
      text-align: left;
    }
    dd {
      marginLeft = 0.px
    }
  }

  // GRID & CONTAINERS
  // -----------------
  // Remove width from containers
  .container {
    width: auto;
  }
  // Fluid rows
  .row-fluid {
    width: 100%;
  }
  // Undo negative margin on rows and thumbnails
  .row .thumbnails {
    marginLeft = 0.px
  }
  .thumbnails > li {
    float: none;
    marginLeft = 0.px // Reset the default margin for all li elements when no .span* classes are present
  }
  // Make all grid-sized elements block level again
  [class*="span"] .uneditable-input[class*="span"], // Makes uneditable inputs full-width when using grid sizing
  .row-fluid [class*="span"] {
    float: none;
    display = Display.block
    width: 100%;
    marginLeft = 0.px
    with(mixins) { boxSizing(border-box) }
  }
  .span12 .row-fluid .span12 {
    width: 100%;
    with(mixins) { boxSizing(border-box) }
  }
  .row-fluid [class*="offset"]:first-child {
    marginLeft = 0.px
  }

  // FORM FIELDS
  // -----------
  // Make span* classes full width
  .input-large .input-xlarge .input-xxlarge input[class*="span"] select[class*="span"] textarea[class*="span"] .uneditable-input {
    with(mixins) { inputBlockLevel() }
  }
  // But don't let it screw up prepend/append inputs
  .input-prepend input .input-append input .input-prepend input[class*="span"] .input-append input[class*="span"] {
    display = Display.inlineBlock // redeclare so they don't wrap to new lines
    width: auto;
  }
  .controls-row [class*="span"] + [class*="span"] {
    marginLeft = 0.px
  }

  // Modals
  .modal {
    position = Position.fixed
    top = 20.px
    left = 20.px
    right = 20.px
    width: auto;
    margin = Margin(0.px)
    &.fade  { top = -100.px
 }
    &.fade.in { top = 20.px
 }
  }

}



// UP TO LANDSCAPE PHONE

vars.media (max-width: 480px) {

  // Smooth out the collapsing/expanding nav
  .nav-collapse {
    -webkit-transform: translate3d(0, 0, 0px);
 // activate the GPU
  }

  // Block level the page header small tag for readability
  .page-header h1 small {
    display = Display.block
    lineHeight = vars.baseLineHeight
  }

  // Update checkboxes for iOS
  input[type="checkbox"] input[type="radio"] {
    border = Border(1.px, BorderStyle.solid, Color(#ccc))
  }

  // Remove the horizontal form styles
  .form-horizontal {
    .control-label {
      float: none;
      width: auto;
      paddingTop = 0.px
      text-align: left;
    }
    // Move over all input controls and content
    .controls {
      marginLeft = 0.px
    }
    // Move the options list down to align with labels
    .control-list {
      paddingTop = 0.px // has to be padding because margin collaspes
    }
    // Move over buttons in .form-actions to align with .controls
    .form-actions {
      paddingLeft = 10.px
      paddingRight = 10.px
    }
  }

  // Medias
  // Reset float and spacing to stack
  .media .pull-left .media .pull-right  {
    float: none;
    display = Display.block
    marginBottom = 10.px
  }
  // Remove side margins since we stack instead of indent
  .media-object {
    marginRight = 0.px
    marginLeft = 0.px
  }

  // Modals
  .modal {
    top = 10.px
    left = 10.px
    right = 10.px
  }
  .modal-header .close {
    padding = Padding(10.px)
    margin: -10px;
  }

  // Carousel
  .carousel-caption {
    position = Position.static
  }

}
    */}


    override fun CssBuilder.responsive768px979px(){/*
vars.media (min-width: 768px) and (max-width: 979px) {

  // Fixed grid
  #grid > .core(vars.gridColumnWidth768, vars.gridGutterWidth768);

  // Fluid grid
  #grid > .fluid(vars.fluidGridColumnWidth768, vars.fluidGridGutterWidth768);

  // Input grid
  #grid > .input(vars.gridColumnWidth768, vars.gridGutterWidth768);

  // No need to reset .thumbnails here since it's the same vars.gridGutterWidth

}
    */}


    override fun CssBuilder.responsiveNavbar(){/*
// TABLETS AND BELOW
vars.media (max-width: vars.navbarCollapseWidth) {

  // UNFIX THE TOPBAR
  // ----------------
  // Remove any padding from the body
  body {
    paddingTop = 0.px
  }
  // Unfix the navbars
  .navbar-fixed-top .navbar-fixed-bottom {
    position = Position.static
  }
  .navbar-fixed-top {
    marginBottom = vars.baseLineHeight
  }
  .navbar-fixed-bottom {
    marginTop = vars.baseLineHeight
  }
  .navbar-fixed-top .navbar-inner .navbar-fixed-bottom .navbar-inner {
    padding = Padding(5.px)
  }
  .navbar .container {
    width: auto;
    padding = Padding(0.px)
  }
  // Account for brand name
  .navbar .brand {
    paddingLeft = 10.px
    paddingRight = 10.px
    margin: 0px 0px 0px -5px;
  }

  // COLLAPSIBLE NAVBAR
  // ------------------
  // Nav collapse clears brand
  .nav-collapse {
    clear: both;
  }
  // Block-level the nav
  .nav-collapse .nav {
    float: none;
    margin: 0px 0px (vars.baseLineHeight / 2);
  }
  .nav-collapse .nav > li {
    float: none;
  }
  .nav-collapse .nav > li > a {
    marginBottom = 2.px
  }
  .nav-collapse .nav > .divider-vertical {
    display = Display.none
  }
  .nav-collapse .nav .nav-header {
    color = vars.navbarText
    text-shadow: none;
  }
  // Nav and dropdown links in navbar
  .nav-collapse .nav > li > a .nav-collapse .dropdown-menu a {
    padding = Padding(9.px, 15.px)
    font-weight: bold;
    color = vars.navbarLinkColor
    with(mixins) { borderRadius(3px) }
  }
  // Buttons
  .nav-collapse .btn {
    padding = Padding(4.px, 10.px, 4.px)
    font-weight: normal;
    with(mixins) { borderRadius(vars.baseBorderRadius) }
  }
  .nav-collapse .dropdown-menu li + li a {
    marginBottom = 2.px
  }
  .nav-collapse .nav > li > a:hover .nav-collapse .nav > li > a:focus .nav-collapse .dropdown-menu a:hover .nav-collapse .dropdown-menu a:focus {
    backgroundColor = vars.navbarBackground
  }
  .navbar-inverse .nav-collapse .nav > li > a .navbar-inverse .nav-collapse .dropdown-menu a {
    color = vars.navbarInverseLinkColor
  }
  .navbar-inverse .nav-collapse .nav > li > a:hover .navbar-inverse .nav-collapse .nav > li > a:focus .navbar-inverse .nav-collapse .dropdown-menu a:hover .navbar-inverse .nav-collapse .dropdown-menu a:focus {
    backgroundColor = vars.navbarInverseBackground
  }
  // Buttons in the navbar
  .nav-collapse.in .btn-group {
    marginTop = 5.px
    padding = Padding(0.px)
  }
  // Dropdowns in the navbar
  .nav-collapse .dropdown-menu {
    position = Position.static
    top: auto;
    left: auto;
    float: none;
    display = Display.none
    max-width: none;
    margin = Margin(0.px, 15.px)
    padding = Padding(0.px)
    background-color: transparent;
    border: none;
    with(mixins) { borderRadius(0px) }
    with(mixins) { boxShadow(none) }
  }
  .nav-collapse .open > .dropdown-menu {
    display = Display.block
  }

rule("  .nav-collapse .dropdown-menu:before .nav-collapse .dropdown-menu:after") {
    display = Display.none
  }
  .nav-collapse .dropdown-menu .divider {
    display = Display.none
  }
  .nav-collapse .nav > li > .dropdown-menu {
    &:before &:after {
      display = Display.none
    }
  }
  // Forms in navbar
  .nav-collapse .navbar-form .nav-collapse .navbar-search {
    float: none;
    padding: (vars.baseLineHeight / 2) 15px;
    margin: (vars.baseLineHeight / 2) 0px;
    borderTop = Border(1.px, BorderStyle.solid, Color(solid))
    borderBottom = Border(1.px, BorderStyle.solid, Color(solid))
    with(mixins) { boxShadow(~"inset 0px 1px 0px rgba(255,255,255,.1), 0px 1px 0px rgba(255,255,255,.1)") }
  }
  .navbar-inverse .nav-collapse .navbar-form .navbar-inverse .nav-collapse .navbar-search {
    border-top-color = vars.navbarInverseBackground
    border-bottom-color = vars.navbarInverseBackground
  }
  // Pull right (secondary) nav content
  .navbar .nav-collapse .nav.pull-right {
    float: none;
    marginLeft = 0.px
  }
  // Hide everything in the navbar save .brand and toggle button
         rule(".nav-collapse .nav-collapse.collapse") {
            overflow: hidden;
            height: 0px;
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

    vars.media (min-width: vars.navbarCollapseDesktopWidth) {

        // Required to make the collapsing navbar work on regular desktops
         rule(".nav-collapse.collapse") {
            height: auto !important;
            overflow: visible !important;
        }

    }
    */}


    override fun CssBuilder.responsiveUtilities(){/*
// IE10 Metro responsive
// Required for Windows 8 Metro split-screen snapping with IE10
// Source: http://timkadlec.com/2012/10/ie10-snap-mode-and-responsive-design/
rule("VAR-ms-viewport") {
  width: device-width;
}

// Hide from screenreaders and browsers
// Credit: HTML5 Boilerplate
rule(".hidden") {
  display = Display.none
  visibility: hidden;
}

// Visibility utilities

// For desktops
rule(".visible-phone") { display: none !important;
 }

rule(".visible-tablet") { display: none !important;
 }

rule(".hidden-phone") { }

rule(".hidden-tablet") { }

rule(".hidden-desktop") { display: none !important;
 }

rule(".visible-desktop") { display: inherit !important;
 }

// Tablets & small desktops only
vars.media (min-width: 768px) and (max-width: 979px) {
  // Hide everything else
  .hidden-desktop    { display: inherit !important;
 }
  .visible-desktop   { display: none !important ;
 }
  // Show
  .visible-tablet    { display: inherit !important;
 }
  // Hide
  .hidden-tablet     { display: none !important;
 }
}

// Phones only
vars.media (max-width: 767px) {
  // Hide everything else
  .hidden-desktop    { display: inherit !important;
 }
  .visible-desktop   { display: none !important;
 }
  // Show
  .visible-phone     { display: inherit !important;
 } // Use inherit to restore previous behavior
  // Hide
  .hidden-phone      { display: none !important;
 }
}

// Print utilities
rule(".visible-print") { display: none !important;
 }

rule(".hidden-print") { }

rule("vars.media print") {
  .visible-print  { display: inherit !important;
 }
  .hidden-print   { display: none !important;
 }
}
    */}


    override fun CssBuilder.scaffolding(){/*
// Body reset
rule("body") {
  margin = Margin(0.px)
  font-family: vars.baseFontFamily;
  fontSize = vars.baseFontSize
  lineHeight = vars.baseLineHeight
  color = vars.textColor
  backgroundColor = vars.bodyBackground
}


// Links
rule("a") {
  color = vars.linkColor
  text-decoration: none;
}

rule("a:hover a:focus") {
  color = vars.linkColorHover
  text-decoration: underline;
}


// Images

// Rounded corners
rule(".img-rounded") {
  with(mixins) { borderRadius(6px) }
}

// Add polaroid-esque trim
rule(".img-polaroid") {
  padding = Padding(4.px)
  backgroundColor = Color("#fff")
  border = Border(1.px, BorderStyle.solid, Color(#ccc))
  border: 1px solid rgba(0,0,0,.2);
  with(mixins) { boxShadow(0px 1px 3px rgba(0,0,0,.1)) }
}

// Perfect circle
rule(".img-circle") {
  with(mixins) { borderRadius(500px) }
 // crank the border-radius so it works with most reasonably sized images
}
    */}


    override fun CssBuilder.sprites(){/*
// ICONS
// -----

// All icons receive the styles of the <i> tag with a base class
// of .i and are then given a unique class to add width, height // and background-position. Your resulting HTML will look like
// <i class="icon-inbox"></i>.

// For the white version of the icons, just add the .icon-white class:
// <i class="icon-inbox icon-white"></i>
rule("[class^="icon-"] [class*=" icon-"]") {
  display = Display.inlineBlock
  width: 14px;
  height: 14px;
  with(mixins) { ie7RestoreRightWhitespace() }
  line-height: 14px;
  vertical-align: text-top;
  background-image: url("@{iconSpritePath}");
  background-position: 14px 14px;
  background-repeat: no-repeat;
  marginTop = 1.px
}

/* White icons with optional class, or on hover/focus/active states of certain elements */
rule(".icon-white .nav-pills > .active > a > [class^="icon-"] .nav-pills > .active > a > [class*=" icon-"] .nav-list > .active > a > [class^="icon-"] .nav-list > .active > a > [class*=" icon-"] .navbar-inverse .nav > .active > a > [class^="icon-"] .navbar-inverse .nav > .active > a > [class*=" icon-"] .dropdown-menu > li > a:hover > [class^="icon-"] .dropdown-menu > li > a:focus > [class^="icon-"] .dropdown-menu > li > a:hover > [class*=" icon-"] .dropdown-menu > li > a:focus > [class*=" icon-"] .dropdown-menu > .active > a > [class^="icon-"] .dropdown-menu > .active > a > [class*=" icon-"] .dropdown-submenu:hover > a > [class^="icon-"] .dropdown-submenu:focus > a > [class^="icon-"] .dropdown-submenu:hover > a > [class*=" icon-"] .dropdown-submenu:focus > a > [class*=" icon-"]") {
  background-image: url("@{iconWhiteSpritePath}");
}

rule(".icon-glass") { background-position: 0px      0px;
 }

rule(".icon-music") { background-position: -24px  0px;
 }

rule(".icon-search") { background-position: -48px  0px;
 }

rule(".icon-envelope") { background-position: -72px  0px;
 }

rule(".icon-heart") { background-position: -96px  0px;
 }

rule(".icon-star") { background-position: -120px 0px;
 }

rule(".icon-star-empty") { background-position: -144px 0px;
 }

rule(".icon-user") { background-position: -168px 0px;
 }

rule(".icon-film") { background-position: -192px 0px;
 }

rule(".icon-th-large") { background-position: -216px 0px;
 }

rule(".icon-th") { background-position: -240px 0px;
 }

rule(".icon-th-list") { background-position: -264px 0px;
 }

rule(".icon-ok") { background-position: -288px 0px;
 }

rule(".icon-remove") { background-position: -312px 0px;
 }

rule(".icon-zoom-in") { background-position: -336px 0px;
 }

rule(".icon-zoom-out") { background-position: -360px 0px;
 }

rule(".icon-off") { background-position: -384px 0px;
 }

rule(".icon-signal") { background-position: -408px 0px;
 }

rule(".icon-cog") { background-position: -432px 0px;
 }

rule(".icon-trash") { background-position: -456px 0px;
 }

rule(".icon-home") { background-position: 0px      -24px;
 }

rule(".icon-file") { background-position: -24px  -24px;
 }

rule(".icon-time") { background-position: -48px  -24px;
 }

rule(".icon-road") { background-position: -72px  -24px;
 }

rule(".icon-download-alt") { background-position: -96px  -24px;
 }

rule(".icon-download") { background-position: -120px -24px;
 }

rule(".icon-upload") { background-position: -144px -24px;
 }

rule(".icon-inbox") { background-position: -168px -24px;
 }

rule(".icon-play-circle") { background-position: -192px -24px;
 }

rule(".icon-repeat") { background-position: -216px -24px;
 }

rule(".icon-refresh") { background-position: -240px -24px;
 }

rule(".icon-list-alt") { background-position: -264px -24px;
 }

rule(".icon-lock") { background-position: -287px -24px;
 } // 1px off
rule(".icon-flag") { background-position: -312px -24px;
 }

rule(".icon-headphones") { background-position: -336px -24px;
 }

rule(".icon-volume-off") { background-position: -360px -24px;
 }

rule(".icon-volume-down") { background-position: -384px -24px;
 }

rule(".icon-volume-up") { background-position: -408px -24px;
 }

rule(".icon-qrcode") { background-position: -432px -24px;
 }

rule(".icon-barcode") { background-position: -456px -24px;
 }

rule(".icon-tag") { background-position: 0px      -48px;
 }

rule(".icon-tags") { background-position: -25px  -48px;
 } // 1px off
rule(".icon-book") { background-position: -48px  -48px;
 }

rule(".icon-bookmark") { background-position: -72px  -48px;
 }

rule(".icon-print") { background-position: -96px  -48px;
 }

rule(".icon-camera") { background-position: -120px -48px;
 }

rule(".icon-font") { background-position: -144px -48px;
 }

rule(".icon-bold") { background-position: -167px -48px;
 } // 1px off
rule(".icon-italic") { background-position: -192px -48px;
 }

rule(".icon-text-height") { background-position: -216px -48px;
 }

rule(".icon-text-width") { background-position: -240px -48px;
 }

rule(".icon-align-left") { background-position: -264px -48px;
 }

rule(".icon-align-center") { background-position: -288px -48px;
 }

rule(".icon-align-right") { background-position: -312px -48px;
 }

rule(".icon-align-justify") { background-position: -336px -48px;
 }

rule(".icon-list") { background-position: -360px -48px;
 }

rule(".icon-indent-left") { background-position: -384px -48px;
 }

rule(".icon-indent-right") { background-position: -408px -48px;
 }

rule(".icon-facetime-video") { background-position: -432px -48px;
 }

rule(".icon-picture") { background-position: -456px -48px;
 }

rule(".icon-pencil") { background-position: 0px      -72px;
 }

rule(".icon-map-marker") { background-position: -24px  -72px;
 }

rule(".icon-adjust") { background-position: -48px  -72px;
 }

rule(".icon-tint") { background-position: -72px  -72px;
 }

rule(".icon-edit") { background-position: -96px  -72px;
 }

rule(".icon-share") { background-position: -120px -72px;
 }

rule(".icon-check") { background-position: -144px -72px;
 }

rule(".icon-move") { background-position: -168px -72px;
 }

rule(".icon-step-backward") { background-position: -192px -72px;
 }

rule(".icon-fast-backward") { background-position: -216px -72px;
 }

rule(".icon-backward") { background-position: -240px -72px;
 }

rule(".icon-play") { background-position: -264px -72px;
 }

rule(".icon-pause") { background-position: -288px -72px;
 }

rule(".icon-stop") { background-position: -312px -72px;
 }

rule(".icon-forward") { background-position: -336px -72px;
 }

rule(".icon-fast-forward") { background-position: -360px -72px;
 }

rule(".icon-step-forward") { background-position: -384px -72px;
 }

rule(".icon-eject") { background-position: -408px -72px;
 }

rule(".icon-chevron-left") { background-position: -432px -72px;
 }

rule(".icon-chevron-right") { background-position: -456px -72px;
 }

rule(".icon-plus-sign") { background-position: 0px      -96px;
 }

rule(".icon-minus-sign") { background-position: -24px  -96px;
 }

rule(".icon-remove-sign") { background-position: -48px  -96px;
 }

rule(".icon-ok-sign") { background-position: -72px  -96px;
 }

rule(".icon-question-sign") { background-position: -96px  -96px;
 }

rule(".icon-info-sign") { background-position: -120px -96px;
 }

rule(".icon-screenshot") { background-position: -144px -96px;
 }

rule(".icon-remove-circle") { background-position: -168px -96px;
 }

rule(".icon-ok-circle") { background-position: -192px -96px;
 }

rule(".icon-ban-circle") { background-position: -216px -96px;
 }

rule(".icon-arrow-left") { background-position: -240px -96px;
 }

rule(".icon-arrow-right") { background-position: -264px -96px;
 }

rule(".icon-arrow-up") { background-position: -289px -96px;
 } // 1px off
rule(".icon-arrow-down") { background-position: -312px -96px;
 }

rule(".icon-share-alt") { background-position: -336px -96px;
 }

rule(".icon-resize-full") { background-position: -360px -96px;
 }

rule(".icon-resize-small") { background-position: -384px -96px;
 }

rule(".icon-plus") { background-position: -408px -96px;
 }

rule(".icon-minus") { background-position: -433px -96px;
 }

rule(".icon-asterisk") { background-position: -456px -96px;
 }

rule(".icon-exclamation-sign") { background-position: 0px      -120px;
 }

rule(".icon-gift") { background-position: -24px  -120px;
 }

rule(".icon-leaf") { background-position: -48px  -120px;
 }

rule(".icon-fire") { background-position: -72px  -120px;
 }

rule(".icon-eye-open") { background-position: -96px  -120px;
 }

rule(".icon-eye-close") { background-position: -120px -120px;
 }

rule(".icon-warning-sign") { background-position: -144px -120px;
 }

rule(".icon-plane") { background-position: -168px -120px;
 }

rule(".icon-calendar") { background-position: -192px -120px;
 }

rule(".icon-random") { background-position: -216px -120px;
 width: 16px;
 }

rule(".icon-comment") { background-position: -240px -120px;
 }

rule(".icon-magnet") { background-position: -264px -120px;
 }

rule(".icon-chevron-up") { background-position: -288px -120px;
 }

rule(".icon-chevron-down") { background-position: -313px -119px;
 } // 1px, 1px off
rule(".icon-retweet") { background-position: -336px -120px;
 }

rule(".icon-shopping-cart") { background-position: -360px -120px;
 }

rule(".icon-folder-close") { background-position: -384px -120px;
 width: 16px;
 }

rule(".icon-folder-open") { background-position: -408px -120px;
 width: 16px;
 }

rule(".icon-resize-vertical") { background-position: -432px -119px;
 } // 1px, 1px off
rule(".icon-resize-horizontal") { background-position: -456px -118px;
 } // 1px, 2px off
rule(".icon-hdd") { background-position: 0px      -144px;
 }

rule(".icon-bullhorn") { background-position: -24px  -144px;
 }

rule(".icon-bell") { background-position: -48px  -144px;
 }

rule(".icon-certificate") { background-position: -72px  -144px;
 }

rule(".icon-thumbs-up") { background-position: -96px  -144px;
 }

rule(".icon-thumbs-down") { background-position: -120px -144px;
 }

rule(".icon-hand-right") { background-position: -144px -144px;
 }

rule(".icon-hand-left") { background-position: -168px -144px;
 }

rule(".icon-hand-up") { background-position: -192px -144px;
 }

rule(".icon-hand-down") { background-position: -216px -144px;
 }

rule(".icon-circle-arrow-right") { background-position: -240px -144px;
 }

rule(".icon-circle-arrow-left") { background-position: -264px -144px;
 }

rule(".icon-circle-arrow-up") { background-position: -288px -144px;
 }

rule(".icon-circle-arrow-down") { background-position: -312px -144px;
 }

rule(".icon-globe") { background-position: -336px -144px;
 }

rule(".icon-wrench") { background-position: -360px -144px;
 }

rule(".icon-tasks") { background-position: -384px -144px;
 }

rule(".icon-filter") { background-position: -408px -144px;
 }

rule(".icon-briefcase") { background-position: -432px -144px;
 }

rule(".icon-fullscreen") { background-position: -456px -144px;
 }
    */}


    override fun CssBuilder.tables(){/*
// BASE TABLES
rule("table") {
  max-width: 100%;
  backgroundColor = vars.tableBackground
  border-collapse: collapse;
  border-spacing: 0px;
}

// BASELINE STYLES
rule(".table") {
  width: 100%;
  marginBottom = vars.baseLineHeight
  // Cells
  th td {
    padding = Padding(8.px)
    lineHeight = vars.baseLineHeight
    text-align: left;
    verticalAlign = VerticalAlign.top
    borderTop = Border(1.px, BorderStyle.solid, Color(solid))
  }
  th {
    font-weight: bold;
  }
  // Bottom align for column headings
  thead th {
    verticalAlign = VerticalAlign.bottom
  }
  // Remove top border from thead by default
  caption + thead tr:first-child th caption + thead tr:first-child td colgroup + thead tr:first-child th colgroup + thead tr:first-child td thead:first-child tr:first-child th thead:first-child tr:first-child td {
    borderTop = Border(0.px)
  }
  // Account for multiple tbody instances
  tbody + tbody {
    borderTop = Border(2.px, BorderStyle.solid, Color(solid))
  }

  // Nesting
  .table {
    backgroundColor = vars.bodyBackground
  }
}



// CONDENSED TABLE W/ HALF PADDING
rule(".table-condensed") {
  th td {
    padding = Padding(4.px, 5.px)
  }
}


// BORDERED VERSION
rule(".table-bordered") {
  border = Border(1.px, BorderStyle.solid, vars.tableBorder)
  border-collapse: separate;
 // Done so we can round those corners!
  declarations[*border-collapse] = "collapse"
 // IE7 can't round corners anyway
  borderLeft = Border(0.px)
  with(mixins) { borderRadius(vars.baseBorderRadius) }
  th td {
    borderLeft = Border(1.px, BorderStyle.solid, Color(solid))
  }
  // Prevent a double border
  caption + thead tr:first-child th caption + tbody tr:first-child th caption + tbody tr:first-child td colgroup + thead tr:first-child th colgroup + tbody tr:first-child th colgroup + tbody tr:first-child td thead:first-child tr:first-child th tbody:first-child tr:first-child th tbody:first-child tr:first-child td {
    borderTop = Border(0.px)
  }
  // For first th/td in the first row in the first thead or tbody
  thead:first-child tr:first-child > th:first-child tbody:first-child tr:first-child > td:first-child tbody:first-child tr:first-child > th:first-child {
    with(mixins) { borderTopLeftRadius(vars.baseBorderRadius) }
  }
  // For last th/td in the first row in the first thead or tbody
  thead:first-child tr:first-child > th:last-child tbody:first-child tr:first-child > td:last-child tbody:first-child tr:first-child > th:last-child {
    with(mixins) { borderTopRightRadius(vars.baseBorderRadius) }
  }
  // For first th/td (can be either) in the last row in the last thead, tbody, and tfoot
  thead:last-child tr:last-child > th:first-child tbody:last-child tr:last-child > td:first-child tbody:last-child tr:last-child > th:first-child tfoot:last-child tr:last-child > td:first-child tfoot:last-child tr:last-child > th:first-child {
    with(mixins) { borderBottomLeftRadius(vars.baseBorderRadius) }
  }
  // For last th/td (can be either) in the last row in the last thead, tbody, and tfoot
  thead:last-child tr:last-child > th:last-child tbody:last-child tr:last-child > td:last-child tbody:last-child tr:last-child > th:last-child tfoot:last-child tr:last-child > td:last-child tfoot:last-child tr:last-child > th:last-child {
    with(mixins) { borderBottomRightRadius(vars.baseBorderRadius) }
  }

  // Clear border-radius for first and last td in the last row in the last tbody for table with tfoot
  tfoot + tbody:last-child tr:last-child td:first-child {
    with(mixins) { borderBottomLeftRadius(0px) }
  }
  tfoot + tbody:last-child tr:last-child td:last-child {
    with(mixins) { borderBottomRightRadius(0px) }
  }

  // Special fixes to round the left border on the first td/th
  caption + thead tr:first-child th:first-child caption + tbody tr:first-child td:first-child colgroup + thead tr:first-child th:first-child colgroup + tbody tr:first-child td:first-child {
    with(mixins) { borderTopLeftRadius(vars.baseBorderRadius) }
  }
  caption + thead tr:first-child th:last-child caption + tbody tr:first-child td:last-child colgroup + thead tr:first-child th:last-child colgroup + tbody tr:first-child td:last-child {
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
    tr:hover > td tr:hover > th {
      backgroundColor = vars.tableBackgroundHover
    }
  }
}


// TABLE CELL SIZING

// Reset default grid behavior
rule("table td[class*="span"] table th[class*="span"] .row-fluid table td[class*="span"] .row-fluid table th[class*="span"]") {
  display = Display.tableCell
  float: none;
 // undo default grid column styles
  marginLeft = 0.px // undo default grid column styles
}

// Change the column widths to account for td/th padding
rule(".table td .table th") {
  &.span1     { .tableColumns(1);
 }
  &.span2     { .tableColumns(2);
 }
  &.span3     { .tableColumns(3);
 }
  &.span4     { .tableColumns(4);
 }
  &.span5     { .tableColumns(5);
 }
  &.span6     { .tableColumns(6);
 }
  &.span7     { .tableColumns(7);
 }
  &.span8     { .tableColumns(8);
 }
  &.span9     { .tableColumns(9);
 }
  &.span10    { .tableColumns(10);
 }
  &.span11    { .tableColumns(11);
 }
  &.span12    { .tableColumns(12);
 }
}



// TABLE BACKGROUNDS
// Exact selectors below required to override .table-striped
rule(".table tbody tr") {
  &.success > td {
    backgroundColor = vars.successBackground
  }
  &.error > td {
    backgroundColor = vars.errorBackground
  }
  &.warning > td {
    backgroundColor = vars.warningBackground
  }
  &.info > td {
    backgroundColor = vars.infoBackground
  }
}

// Hover states for .table-hover
rule(".table-hover tbody tr") {
  &.success:hover > td {
    background-color: darken(vars.successBackground, 5%);
  }
  &.error:hover > td {
    background-color: darken(vars.errorBackground, 5%);
  }
  &.warning:hover > td {
    background-color: darken(vars.warningBackground, 5%);
  }
  &.info:hover > td {
    background-color: darken(vars.infoBackground, 5%);
  }
}
    */}


    override fun CssBuilder.thumbnails(){/*
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
  float: left;
 // Explicity set the float since we don't require .span* classes
  marginBottom = vars.baseLineHeight
  marginLeft = vars.gridGutterWidth
}

// The actual thumbnail (can be `a` or `div`)
rule(".thumbnail") {
  display = Display.block
  padding = Padding(4.px)
  lineHeight = vars.baseLineHeight
  border = Border(1.px, BorderStyle.solid, Color(#ddd))
  with(mixins) { borderRadius(vars.baseBorderRadius) }
  with(mixins) { boxShadow(0px 1px 3px rgba(0,0,0,.055)) }
  with(mixins) { transition(all .2s ease-in-out) }
}
// Add a hover/focus state for linked versions only
rule("a.thumbnail:hover a.thumbnail:focus") {
  borderColor =  vars.linkColor
  with(mixins) { boxShadow(0px 1px 4px rgba(0,105,214,.25)) }
}

// Images and captions
rule(".thumbnail > img") {
  display = Display.block
  max-width: 100%;
  marginLeft = LinearDimension.auto
  marginRight = LinearDimension.auto
}

rule(".thumbnail .caption") {
  padding = Padding(9.px)
  color = vars.gray
}
    */}


    override fun CssBuilder.tooltip(){/*
// Base class
rule(".tooltip") {
  position = Position.absolute
  z-index: vars.zindexTooltip;
  display = Display.block
  visibility: visible;
  fontSize = 11.px
  lineHeight = 1.4.px
  with(mixins) { opacity(0px) }
  &.in     { .opacity(80);
 }
  &.top    { marginTop = -3.px
 padding = Padding(5.px, 0.px) }
  &.right  { marginLeft = 3.px
 padding = Padding(0.px, 5.px) }
  &.bottom { marginTop = 3.px
 padding = Padding(5.px, 0.px) }
  &.left   { marginLeft = -3.px
 padding = Padding(0.px, 5.px) }
}

// Wrapper for the tooltip content
rule(".tooltip-inner") {
  max-width: 200px;
  padding = Padding(8.px)
  color = vars.tooltipColor
  text-align: center;
  text-decoration: none;
  backgroundColor = vars.tooltipBackground
  with(mixins) { borderRadius(vars.baseBorderRadius) }
}

// Arrows
rule(".tooltip-arrow") {
  position = Position.absolute
  width: 0px;
  height: 0px;
  border-color: transparent;
  border-style: solid;
}

rule(".tooltip") {
  &.top .tooltip-arrow {
    bottom = 0.px
    left: 50%;
    marginLeft = -vars.tooltipArrowWidth
    border-width: vars.tooltipArrowWidth vars.tooltipArrowWidth 0px;
    border-top-color = vars.tooltipArrowColor
  }
  &.right .tooltip-arrow {
    top: 50%;
    left = 0.px
    marginTop = -vars.tooltipArrowWidth
    border-width: vars.tooltipArrowWidth vars.tooltipArrowWidth vars.tooltipArrowWidth 0px;
    border-right-color = vars.tooltipArrowColor
  }
  &.left .tooltip-arrow {
    top: 50%;
    right = 0.px
    marginTop = -vars.tooltipArrowWidth
    border-width: vars.tooltipArrowWidth 0px vars.tooltipArrowWidth vars.tooltipArrowWidth;
    border-left-color = vars.tooltipArrowColor
  }
  &.bottom .tooltip-arrow {
    top = 0.px
    left: 50%;
    marginLeft = -vars.tooltipArrowWidth
    border-width: 0px vars.tooltipArrowWidth vars.tooltipArrowWidth;
    border-bottom-color = vars.tooltipArrowColor
  }
}
    */}


    override fun CssBuilder.type(){/*
// Body text
rule("p") {
  margin: 0px 0px vars.baseLineHeight / 2;
}

rule(".lead") {
  marginBottom = vars.baseLineHeight
  fontSize = vars.baseFontSize * 1.5
  font-weight: 200;
  line-height: vars.baseLineHeight * 1.5;
}


// Emphasis & misc

// Ex: 14px base font * 85% = about 12px
rule("small") { fontSize = 85.pct
 }

rule("strong") { font-weight: bold;
 }

rule("em") { font-style: italic;
 }

rule("cite") { font-style: normal;
 }

// Utility classes
rule(".muted") { color = vars.grayLight
 }

rule("a.muted:hover a.muted:focus") { color: darken(vars.grayLight, 10%);
 }

rule(".text-warning") { color = vars.warningText
 }

rule("a.text-warning:hover a.text-warning:focus") { color: darken(vars.warningText, 10%);
 }

rule(".text-error") { color = vars.errorText
 }

rule("a.text-error:hover a.text-error:focus") { color: darken(vars.errorText, 10%);
 }

rule(".text-info") { color = vars.infoText
 }

rule("a.text-info:hover a.text-info:focus") { color: darken(vars.infoText, 10%);
 }

rule(".text-success") { color = vars.successText
 }

rule("a.text-success:hover a.text-success:focus") { color: darken(vars.successText, 10%);
 }

rule(".text-left") { text-align: left;
 }

rule(".text-right") { text-align: right;
 }

rule(".text-center") { text-align: center;
 }


// Headings
rule("h1, h2, h3, h4, h5, h6") {
  margin: (vars.baseLineHeight / 2) 0px;
  font-family: vars.headingsFontFamily;
  font-weight: vars.headingsFontWeight;
  lineHeight = vars.baseLineHeight
  color = vars.headingsColor
  text-rendering: optimizelegibility;
 // Fix the character spacing for headings
  small {
    font-weight: normal;
    lineHeight = 1.px
    color = vars.grayLight
  }
}

rule("h1 h2 h3") { line-height: vars.baseLineHeight * 2;
 }

rule("h1") { fontSize = vars.baseFontSize * 2.75
 } // ~38px
rule("h2") { fontSize = vars.baseFontSize * 2.25
 } // ~32px
rule("h3") { fontSize = vars.baseFontSize * 1.75
 } // ~24px
rule("h4") { fontSize = vars.baseFontSize * 1.25
 } // ~18px
rule("h5") { fontSize = vars.baseFontSize
 }

rule("h6") { fontSize = vars.baseFontSize * 0.85
 } // ~12px
rule("h1 small") { fontSize = vars.baseFontSize * 1.75
 } // ~24px
rule("h2 small") { fontSize = vars.baseFontSize * 1.25
 } // ~18px
rule("h3 small") { fontSize = vars.baseFontSize
 }

rule("h4 small") { fontSize = vars.baseFontSize
 }


// Page header
rule(".page-header") {
  padding-bottom: (vars.baseLineHeight / 2)-1;
  margin: vars.baseLineHeight 0px (vars.baseLineHeight * 1.5);
  borderBottom = Border(1.px, BorderStyle.solid, Color(solid))
}



// Lists

// Unordered and Ordered lists
rule("ul, ol") {
  padding = Padding(0.px)
  margin: 0px 0px vars.baseLineHeight / 2 25px;
}

rule("ul ul ul ol ol ol ol ul") {
  marginBottom = 0.px
}

rule("li") {
  lineHeight = vars.baseLineHeight
}

// Remove default list styles
rule("ul.unstyled ol.unstyled") {
  marginLeft = 0.px
  listStyleType = ListStyleType.none
}

// Single-line list items
rule("ul.inline ol.inline") {
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

rule("dt dd") {
  lineHeight = vars.baseLineHeight
}

rule("dt") {
  font-weight: bold;
}

rule("dd") {
  margin-left: vars.baseLineHeight / 2;
}
// Horizontal layout (like forms)
rule(".dl-horizontal") {
  with(mixins) { clearfix() }
 // Ensure dl clears floats if empty dd elements present
  dt {
    float: left;
    width: vars.horizontalComponentOffset-20;
    clear: left;
    text-align: right;
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
  margin: vars.baseLineHeight 0px;
  border: 0px;
  borderTop = Border(1.px, BorderStyle.solid, Color(solid))
  borderBottom = Border(1.px, BorderStyle.solid, Color(solid))
}

// Abbreviations and acronyms
abbr[title] // Added data-* attribute to help out our tooltip plugin, per https://github.com/twbs/bootstrap/issues/5257
rule("abbr[data-original-title]") {
  cursor = Cursor.help
  borderBottom = Border(1.px, BorderStyle.solid, Color(dotted))
}

rule("abbr.initialism") {
  fontSize = 90.pct
  text-transform: uppercase;
}

// Blockquotes
rule("blockquote") {
  padding = Padding(0.px, 0.px, 0.px, 15.px)
  margin: 0px 0px vars.baseLineHeight;
  borderLeft = Border(5.px, BorderStyle.solid, Color(solid))
  p {
    marginBottom = 0.px
    fontSize = vars.baseFontSize * 1.25
    font-weight: 300;
    lineHeight = 1.25.px
  }
  small {
    display = Display.block
    lineHeight = vars.baseLineHeight
    color = vars.grayLight
    &:before {
      content: '\2014 \00A0';
    }
  }

  // Float right with text-align: right
  &.pull-right {
    float: right;
    paddingRight = 15.px
    paddingLeft = 0.px
    borderRight = Border(5.px, BorderStyle.solid, Color(solid))
    borderLeft = Border(0.px)
    p small {
      text-align: right;
    }
    small {
      &:before {
        content: '';
      }
      &:after {
        content: '\00A0 \2014';
      }
    }
  }
}

// Quotes
rule("q:before q:after blockquote:before blockquote:after") {
  content: "";
}

// Addresses
rule("address") {
  display = Display.block
  marginBottom = vars.baseLineHeight
  font-style: normal;
  lineHeight = vars.baseLineHeight
}
    */}


    override fun CssBuilder.utilities(){/*
// Quick floats
rule(".pull-right") {
  float: right;
}

rule(".pull-left") {
  float: left;
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
  visibility: hidden;
}

// For Affix plugin
rule(".affix") {
  position = Position.fixed
}
    */}


    override fun CssBuilder.variables(){/**/}


    override fun CssBuilder.wells(){/*
// Base class
rule(".well") {
  min-height: 20px;
  padding = Padding(19.px)
  marginBottom = 20.px
  backgroundColor = vars.wellBackground
  border: 1px solid darken(vars.wellBackground, 7%);
  with(mixins) { borderRadius(vars.baseBorderRadius) }
  with(mixins) { boxShadow(inset 0px 1px 1px rgba(0,0,0,.05)) }
  blockquote {
    borderColor = Color("#ddd")
    border-color: rgba(0,0,0,.15);
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
    */}

}
