package io.github.pdvrieze.openid.web.style.default

import io.github.pdvrieze.openid.web.style.Mixins
import io.github.pdvrieze.openid.web.style.Styles
import kotlinx.css.*
import kotlinx.css.Float
import kotlinx.css.properties.*

object DefaultMixins: Mixins {

    //region Utility Mixins
    /**
     * For clearing floats like a boss h5bp.com/q
     */
    override fun CssBuilder.clearfix() {
        display = Display.table

        rule("&:before &:after") {
            display = Display.table
            content = QuotedString("")
            // Fixes Opera/contenteditable bug:
            // http://nicolasgallagher.com/micro-clearfix-hack/#comment-36952
            lineHeight = 0.px.lh;
        }
        rule("&:after") {
            clear = Clear.both
        }
    }

    /** Webkit-style focus */
    override fun CssBuilder.tabFocus() {
        // Default
        outlineWidth = LinearDimension("thin")
        outlineStyle = OutlineStyle.dotted
        outlineColor = Color("#333")

        // Webkit
        declarations["outline"] = "5px auto -webkit-focus-ring-color"
        outlineOffset = -2.px;
    }

    /** Center-align a block level element */
    override fun CssBuilder.centerBlock() {
      display = Display.block
      marginLeft = LinearDimension.auto
      marginRight = LinearDimension.auto
    }

    /** IE7 inline-block */
    override fun CssBuilder.ie7InlineBlock() {
        declarations["*display"] = Display.inline /* IE7 inline-block hack */
        declarations["*zoom"] = 1
    }

    /**
     * IE7 likes to collapse whitespace on either side of the inline-block elements.
     * Ems because we're attempting to match the width of a space character. Left
     * version is for form buttons, which typically come after other elements, and
     * right version is for icons, which come before. Applying both is ok, but it will
     * mean that space between those elements will be 0.6.em (~2 space characters) in IE7 // instead of the 1 space in other browsers.
     */
    override fun CssBuilder.ie7RestoreLeftWhitespace() {
        declarations["*margin-left"] = 0.3.em
        rule("  &:first-child") {
            declarations["*margin-left"] = 0.px
        }
    }

    override fun CssBuilder.ie7RestoreRightWhitespace() {
        declarations["*margin-right"] = 0.3.em
    }

    /** Sizing shortcuts */
    override fun CssBuilder.size(height: LinearDimension,  width: LinearDimension) {
        this.width = width
        this.height = height
    }

    override fun CssBuilder.square(size: LinearDimension) {
        size(size, size)
    }

    /** Placeholder text */
    override fun CssBuilder.placeholder(color: Color) {
        rule("&:-moz-placeholder") {
            this.color = color
        }
        rule("&:-ms-input-placeholder") {
            this.color = color
        }
        rule("&::-webkit-input-placeholder") {
            this.color = color
        }
    }

    /**
     * Text overflow.
     *
     * Requires inline-block or block for proper styling
     */
    override fun CssBuilder.textOverflow() {
        overflow = Overflow.hidden
        textOverflow = TextOverflow.ellipsis
        whiteSpace = WhiteSpace.nowrap
    }

    /**
     * CSS image replacement.
     * Source: https://github.com/h5bp/html5-boilerplate/commit/aa0396eae757
     */
    override fun CssBuilder.hideText() {
        declarations["font"] = "0/0px a"
        color = Color.transparent
        declarations["text-shadow"] = "none"
        backgroundColor = Color.transparent;
        borderWidth = 0.px;
    }
    //endregion

    //region Fonts

    override fun CssBuilder.fontFamilySerif(vars: Styles.Vars) {
        fontFamily = vars.serifFontFamily;
    }

    override fun CssBuilder.fontFamilySansSerif(vars: Styles.Vars) {
        fontFamily = vars.sansFontFamily;
    }

    override fun CssBuilder.fontFamilyMonospace(vars: Styles.Vars) {
        fontFamily = vars.monoFontFamily;
    }

    override fun CssBuilder.fontShorthand(
        size: LinearDimension,
        weight: FontWeight,
        lineHeight: LineHeight,
    ) {
        this.fontSize = size
        this.fontWeight= weight
        this.lineHeight = lineHeight
    }

    override fun CssBuilder.serif(
        vars: Styles.Vars,
        weight: FontWeight,
        size: LinearDimension,
        lineHeight: LineHeight,
    ) {
        fontFamilySerif(vars)
        fontShorthand(size, weight, lineHeight)
    }

    override fun CssBuilder.sansSerif(
        vars: Styles.Vars,
        weight: FontWeight,
        size: LinearDimension,
        lineHeight: LineHeight,
    ) {
        fontFamilySansSerif(vars)
        fontShorthand(size, weight, lineHeight)
    }
    override fun CssBuilder.monospace(
        vars: Styles.Vars,
        weight: FontWeight,
        size: LinearDimension,
        lineHeight: LineHeight,
    ) {
        fontFamilyMonospace(vars)
        fontShorthand(size, weight, lineHeight)
    }
    //endregion

    //region Forms
    /** Block level inputs */
    override fun CssBuilder.inputBlockLevel(inputHeight: LinearDimension) {
        display = Display.block
        width = 100.pct
        minHeight = inputHeight // Make inputs at least the height of their button counterpart (base line-height + padding + border)
        boxSizing(BoxSizing.borderBox) // Makes inputs behave like true block-level elements
    }

    override val mixins: DefaultMixins get() = this

    override fun CssBuilder.formFieldState(
        textColor: Color,
        borderColor: Color,
        backgroundColor: Color
    ) {
        
        // Set the text color
        ".control-label.help-block.help-inline" {
            color = textColor
        }
        // Mixin for form field states
        // Style inputs accordingly
        ".checkbox .radio input select textarea" {
            color = textColor
        }
        "input select textarea" {
            this.borderColor =  borderColor
            boxShadow += BoxShadowInset(
                color = rgb(0, 0, 0, .075),
                offsetX = 0.px,
                offsetY = 1.px,
                blurRadius = 1.px,
            )
        // Redeclare so transitions work
            focus {
                this.borderColor = borderColor.darken(10)
                boxShadow += BoxShadowInset(rgb(0,0,0,.075), 0.px, 1.px, 1.px)
                boxShadow += BoxShadowInset(borderColor.lighten(20), 0.px, 0.px, 6.px)
            }
        }

        // Give a small background color for input-prepend/-append
        ".input-prepend .add-on .input-append .add-on" {
            color = textColor
            this.backgroundColor = backgroundColor
            this.borderColor =  textColor
        }
    }
    //endregion

    //region Css3 properties


    /** Border Radius */
    override fun CssBuilder.borderRadius(radius: LinearDimension) {
        declarations["-webkit-border-radius"] = radius
        declarations["-moz-border-radius"] = radius
        borderRadius = radius
    }

    // Single Corner Border Radius
    override fun CssBuilder.borderTopLeftRadius(radius: LinearDimension) {
        declarations["-webkit-border-top-left-radius"] = radius
        declarations["-moz-border-radius-topleft"] = radius
        borderTopLeftRadius = radius
    }

    override fun CssBuilder.borderTopRightRadius(radius: LinearDimension) {
        declarations["-webkit-border-top-right-radius"] = radius
        declarations["-moz-border-radius-topright"] = radius
        borderTopRightRadius = radius
    }

    override fun CssBuilder.borderBottomRightRadius(radius: LinearDimension) {
        declarations["-webkit-border-bottom-right-radius"] = radius
        declarations["-moz-border-radius-bottomright"] = radius
        borderBottomRightRadius = radius
    }

    override fun CssBuilder.borderBottomLeftRadius(radius: LinearDimension) {
        declarations["-webkit-border-bottom-left-radius"] = radius
        declarations["-moz-border-radius-bottomleft"] = radius
        borderBottomLeftRadius = radius
    }

    // Single Side Border Radius
    override fun CssBuilder.borderTopRadius(radius: LinearDimension) {
        borderTopRightRadius(radius)
        borderTopLeftRadius(radius)
    }
    override fun CssBuilder.borderRightRadius(radius: LinearDimension) {
        borderTopRightRadius(radius)
        borderBottomRightRadius(radius)
    }
    override fun CssBuilder.borderBottomRadius(radius: LinearDimension) {
        borderBottomRightRadius(radius)
        borderBottomLeftRadius(radius)
    }
    override fun CssBuilder.borderLeftRadius(radius: LinearDimension) {
        borderTopLeftRadius(radius)
        borderBottomLeftRadius(radius)
    }

    // Drop shadows
    override fun CssBuilder.boxShadow(shadow: BoxShadows) {
        declarations["-webkit-box-shadow"] = shadow
        declarations["-moz-box-shadow"] = shadow
        boxShadow = shadow
    }

    // Transitions
    override fun CssBuilder.transition(transition: String) {
        declarations["-webkit-transition"] = transition
        declarations["-moz-transition"] = transition
        declarations["-o-transition"] = transition
        declarations["transition"] = transition
    }

    override fun CssBuilder.transition(property: String, duration: Time, timing: Timing) {
        declarations["-webkit-transition"] = "$property $duration $timing"
        declarations["-moz-transition"] = "$property $duration $timing"
        declarations["-o-transition"] = "$property $duration $timing"
        declarations["transition"] = "$property $duration $timing"
    }

    override fun CssBuilder.transitionDelay(transitionDelay: Time) {
        declarations["-webkit-transition-delay"] = transitionDelay
        declarations["-moz-transition-delay"] = transitionDelay
        declarations["-o-transition-delay"] = transitionDelay
        this.transitionDelay = transitionDelay
    }

    override fun CssBuilder.transitionDuration(transitionDuration: Time) {
        declarations["-webkit-transition-duration"] = transitionDuration
        declarations["-moz-transition-duration"] = transitionDuration
        declarations["-o-transition-duration"] = transitionDuration
        this.transitionDuration = transitionDuration
    }

    // Transformations
    override fun CssBuilder.rotate(degrees: Angle) {
        declarations["-webkit-transform"] = "rotate($degrees)"
        declarations["-moz-transform"] = "rotate($degrees)"
        declarations["-ms-transform"] = "rotate($degrees)"
        declarations["-o-transform"] = "rotate($degrees)"
        transform { rotate(degrees) }
    }

    override fun CssBuilder.scale(ratio: Double) {
        declarations["-webkit-transform"] = "scale($ratio)"
        declarations["-moz-transform"] = "scale($ratio)"
        declarations["-ms-transform"] = "scale($ratio)"
        declarations["-o-transform"] = "scale($ratio)"
        declarations["transform"] = "scale($ratio)"
        transform { scale(ratio) }
    }

    override fun CssBuilder.translateM(x: LinearDimension, y: LinearDimension) {
        declarations["-webkit-transform"] = "translate($x, $y)"
        declarations["-moz-transform"] = "translate($x, $y)"
        declarations["-ms-transform"] = "translate($x, $y)"
        declarations["-o-transform"] = "translate($x, $y)"
        transform { translate(x, y) }
    }

    override fun CssBuilder.skew(x: Angle, y: Angle) {
        declarations["-webkit-transform"] = "skew($x, $y)"
        declarations["-moz-transform"] = "skew($x, $y)"
        declarations["-ms-transform"] = "skewX($x) skewY($y)" // See https://github.com/twbs/bootstrap/issues/4885
        declarations["-o-transform"] = "skew($x, $y)"
        transform { skew(x, y) }
        declarations["transform"] = "skew($x, $y)"
        declarations["-webkit-backface-visibility"] = "hidden" // See https://github.com/twbs/bootstrap/issues/5319
    }

    override fun CssBuilder.translate3d(x: LinearDimension, y: LinearDimension, z: LinearDimension) {
        declarations["-webkit-transform"] = "translate3d($x, $y, $z)"
        declarations["-moz-transform"] = "translate3d($x, $y, $z)"
        declarations["-o-transform"] = "translate3d($x, $y, $z)"
        transform { translate3d(x, y, z) }
    }

    /**
     * Backface visibility
     * Prevent browsers from flickering when using CSS 3D transforms.
     * Default value is `visible`, but can be changed to `hidden
     * See git pull https://github.com/dannykeane/bootstrap.git backface-visibility for examples
     */
    override fun CssBuilder.backfaceVisibility(visibility: Visibility){
        declarations["-webkit-backface-visibility"] = visibility
        declarations["-moz-backface-visibility"] = visibility
        backfaceVisibility = visibility
    }

    /**
     * Background clipping
     * Heads up: FF 3.6 and under need "padding" instead of "padding-box"
     */
    override fun CssBuilder.backgroundClip(clip: BackgroundClip) {
        declarations["-webkit-background-clip"] = clip
        declarations["-moz-background-clip"] = clip
        backgroundClip = clip
    }

    /** Background sizing */
    override fun CssBuilder.backgroundSize(size: String) {
        declarations["-webkit-background-size"] = size
        declarations["-moz-background-size"] = size
        declarations["-o-background-size"] = size
        backgroundSize = size
    }


    /** Box sizing */
    override fun CssBuilder.boxSizing(boxmodel: BoxSizing) {
        declarations["-webkit-box-sizing"] = boxmodel
        declarations["-moz-box-sizing"] = boxmodel
        boxSizing = boxmodel
    }

    /**
     * User select
     * For selecting text on the page
     */
    override fun CssBuilder.userSelect(select: UserSelect) {
        declarations["-webkit-user-select"] = select
        declarations["-moz-user-select"] = select
        declarations["-ms-user-select"] = select
        declarations["-o-user-select"] = select
        userSelect = select
    }

    /** Resize anything */
    override fun CssBuilder.resizable(direction: Resize) {
        resize = direction // Options: horizontal, vertical, both
        overflow = Overflow.auto // Safari fix
    }

    /** CSS3 Content Columns */
    override fun CssBuilder.contentColumns(columnCount: Int, columnGap: LinearDimension) {
        declarations["-webkit-column-count"] = columnCount
        declarations["-moz-column-count"] = columnCount
        declarations["column-count"] = columnCount

        declarations["-webkit-column-gap"] = columnGap
        declarations["-moz-column-gap"] = columnGap
        this.columnGap = columnGap
    }

    /**
     * Overload for automatic column count (based upon sizes)
     */
    override fun CssBuilder.autoContentColumns(columnGap: LinearDimension) {
        declarations["-webkit-column-count"] = "auto"
        declarations["-moz-column-count"] = "auto"
        declarations["column-count"] = "auto"

        declarations["-webkit-column-gap"] = columnGap
        declarations["-moz-column-gap"] = columnGap
        this.columnGap = columnGap
    }

    // Optional hyphenation
    override fun CssBuilder.hyphens(mode: Hyphens) {
        wordWrap = WordWrap.breakWord

        declarations["-webkit-hyphens"] = mode
        declarations["-moz-hyphens"] = mode
        declarations["-ms-hyphens"] = mode
        declarations["-o-hyphens"] = mode
        declarations["hyphens"] = mode
        hyphens = mode
    }

    // Opacity
    override fun CssBuilder.opacity(opacity: Number) {
        filter = "opacity($opacity%)"
        filter = "alpha(opacity=$opacity%)"
    }
    //endregion

    //region Backgrounds

    // Add an alphatransparency value to any background or border color (via Elyse Holladay)
    override fun CssBuilder.translucentBackground(color: Color, alpha: Double) {
        backgroundColor = color.changeAlpha(alpha)
    }
    
    override fun CssBuilder.translucentBorder(color: Color, alpha: Double) {
        borderColor = color.changeAlpha(alpha)
        backgroundClip(BackgroundClip.paddingBox)
    }

    /** Gradient Bar Colors for buttons and alerts */
    override fun CssBuilder.gradientBar(
        primaryColor: Color,
        secondaryColor: Color,
        textColor: Color,
        textShadow: String,
    ) {
        color = textColor
        declarations["textShadow"] = textShadow
        gradientVertical(primaryColor, secondaryColor)
        declarations["border-color"] = "secondaryColor secondaryColor darken(secondaryColor, 15%)"
        declarations["border-color"] = "rgba(0,0,0,.1) rgba(0,0,0,.1) fadein(rgba(0,0,0,.1), 15%)"
    }

    override fun CssBuilder.gradientHorizontal(startColor: Color, endColor: Color) {
        backgroundColor = endColor
        backgroundImage = Image("-moz-linear-gradient(left, startColor, endColor)") // FF 3.6+
        backgroundImage = Image("-webkit-gradient(linear, 0px 0, 100% 0, from(startColor), to(endColor))") // Safari 4+, Chrome 2+
        backgroundImage = Image("-webkit-linear-gradient(left, startColor, endColor)") // Safari 5.1+, Chrome 10+
        backgroundImage = Image("-o-linear-gradient(left, startColor, endColor)") // Opera 11.10
        backgroundImage = Image("linear-gradient(to right, startColor, endColor)") // Standard, IE10
        backgroundRepeat = BackgroundRepeat.repeatX

        // IE9 and down
        filter = """e(%("progid:DXImageTransform.Microsoft.gradient(startColorstr='%d', endColorstr='%d', GradientType=1)",argb(@startColor),argb(@endColor)))"""
    }

    override fun CssBuilder.gradientVertical(startColor: Color, endColor: Color) {
        declarations["background-color"] = "mix(startColor, endColor, 60%)"
        backgroundImage = Image("-moz-linear-gradient(top, startColor, endColor)") // FF 3.6+
        backgroundImage = Image("-webkit-gradient(linear, 0px 0, 0px 100%, from(startColor), to(endColor))") // Safari 4+, Chrome 2+
        backgroundImage = Image("-webkit-linear-gradient(top, startColor, endColor)") // Safari 5.1+, Chrome 10+
        backgroundImage = Image("-o-linear-gradient(top, startColor, endColor)") // Opera 11.10
        backgroundImage = Image("linear-gradient(to bottom, startColor, endColor)") // Standard, IE10
        backgroundRepeat = BackgroundRepeat.repeatX

        // IE9 and down
        filter =
            """e(%("progid:DXImageTransform.Microsoft.gradient(startColorstr='%d', endColorstr='%d', GradientType=0)",argb(@startColor),argb(@endColor)));"""
    }

    override fun CssBuilder.gradientDirectional(
        startColor: Color,
        endColor: Color,
        deg: Angle,
    ) {
        backgroundColor = endColor
        backgroundRepeat = BackgroundRepeat.repeatX
        backgroundImage = Image("-moz-linear-gradient(deg, startColor, endColor)")
        // FF 3.6+
        backgroundImage = Image("-webkit-linear-gradient(deg, startColor, endColor)")
        // Safari 5.1+, Chrome 10+
        backgroundImage = Image("-o-linear-gradient(deg, startColor, endColor)")
        // Opera 11.10
        backgroundImage = Image("linear-gradient(deg, startColor, endColor)")
        // Standard, IE10
    }
    override fun CssBuilder.gradientHorizontalThreeColors(
        startColor: Color,
        midColor: Color,
        colorStop: LinearDimension,
        endColor: Color
    ) {
        backgroundColor = Color("mix(midColor, endColor, 80%)")
        backgroundImage = Image("-webkit-gradient(left, linear, 0px 0, 0px 100%, from($startColor), color-stop($colorStop, $midColor), to($endColor))")
        backgroundImage = Image("-webkit-linear-gradient(left, $startColor, $midColor $colorStop, $endColor)")
        backgroundImage = Image("-moz-linear-gradient(left, $startColor, $midColor $colorStop, $endColor)")
        backgroundImage = Image("-o-linear-gradient(left, $startColor, $midColor $colorStop, $endColor)")
        backgroundImage = linearGradient(GradientSideOrCorner.ToRight) {
            colorStop(startColor)
            colorStop(midColor, colorStop)
            colorStop(endColor)
        }
        backgroundRepeat = BackgroundRepeat.noRepeat

        // IE9 and down, gets no color-stop at all for proper fallback
        filter = """e(%("progid:DXImageTransform.Microsoft.gradient(startColorstr='%d', endColorstr='%d', GradientType=0)",argb(@startColor),argb(@endColor)))"""
    }

    override fun CssBuilder.gradientVerticalThreeColors(
        startColor: Color,
        midColor: Color,
        colorStop: LinearDimension,
        endColor: Color
    ) {
        backgroundColor = Color("mix(midColor, endColor, 80%)")
        backgroundImage = Image("-webkit-gradient(left, linear, 0px 0, 0px 100%, from($startColor), color-stop($colorStop, $midColor), to($endColor))")
        backgroundImage = Image("-webkit-linear-gradient(left, $startColor, $midColor $colorStop, $endColor)")
        backgroundImage = Image("-moz-linear-gradient(top, $startColor, $midColor $colorStop, $endColor)")
        backgroundImage = Image("-o-linear-gradient(left, $startColor, $midColor $colorStop, $endColor)")
        backgroundImage = linearGradient {
            colorStop(startColor)
            colorStop(midColor, colorStop)
            colorStop(endColor)
        }
        backgroundRepeat = BackgroundRepeat.noRepeat

        // IE9 and down, gets no color-stop at all for proper fallback
        filter = """e(%("progid:DXImageTransform.Microsoft.gradient(startColorstr='%d', endColorstr='%d', GradientType=0)",argb(@startColor),argb(@endColor)))"""
    }

    override fun CssBuilder.gradientRadial(innerColor: Color, outerColor: Color) {
        backgroundColor = outerColor
        backgroundImage = Image("-webkit-gradient(radial, center center, 0, center center, 460, from($innerColor), to($outerColor))")
        backgroundImage = Image("-webkit-radial-gradient(circle, $innerColor, $outerColor)")
        backgroundImage = Image("-moz-radial-gradient(circle, $innerColor, $outerColor)")
        backgroundImage = Image("-o-radial-gradient(circle, $innerColor, $outerColor)")
        backgroundImage = radialGradient {
            circle()
            colorStop(innerColor)
            colorStop(outerColor)
        }
        backgroundRepeat = BackgroundRepeat.noRepeat
    }

    override fun CssBuilder.gradientStriped(color: Color, angle: Angle) {
        backgroundColor = color
        backgroundImage = Image("-webkit-gradient(linear, 0px 100%, 100% 0, color-stop(.25, rgba(255,255,255,.15)), color-stop(.25, transparent), color-stop(.5, transparent), color-stop(.5, rgba(255,255,255,.15)), color-stop(.75, rgba(255,255,255,.15)), color-stop(.75, transparent), to(transparent))")
        backgroundImage = Image("-webkit-linear-gradient($angle, rgba(255,255,255,.15) 25%, transparent 25%, transparent 50%, rgba(255,255,255,.15) 50%, rgba(255,255,255,.15) 75%, transparent 75%, transparent)")
        backgroundImage = Image("-moz-linear-gradient($angle, rgba(255,255,255,.15) 25%, transparent 25%, transparent 50%, rgba(255,255,255,.15) 50%, rgba(255,255,255,.15) 75%, transparent 75%, transparent)")
        backgroundImage = Image("-o-linear-gradient($angle, rgba(255,255,255,.15) 25%, transparent 25%, transparent 50%, rgba(255,255,255,.15) 50%, rgba(255,255,255,.15) 75%, transparent 75%, transparent)")

        backgroundImage = linearGradient(angle) {
            colorStop(rgb(255, 255, 255, 0.15), 25.pct)
            colorStop(Color.transparent, 25.pct)
            colorStop(Color.transparent, 50.pct)
            colorStop(rgb(255, 255, 255, 0.15), 50.pct)
            colorStop(rgb(255, 255, 255, 0.15), 75.pct)
            colorStop(Color.transparent, 75.pct)
            colorStop(Color.transparent)
        }
    }

    /** Reset filters for IE */
    override fun CssBuilder.resetFilter() {
        filter = """e(%("progid:DXImageTransform.Microsoft.gradient(enabled = false)"));"""
    }
    //endregion


    //region Component mixins

    /**
     * Horizontal dividers
     * Dividers (basically an hr) within dropdowns and nav lists
     */
    override fun CssBuilder.navDivider(
        top: Color,
        bottom: Color,
        baselineHeight: LinearDimension,
    ) {
    // IE7 needs a set width since we gave a height. Restricting just
    // to IE7 to keep the 1px left/right space in other browsers.
    // It is unclear where IE is getting the extra space that we need
    // to negative-margin away, but so it goes.
        declarations["*width"] = 100.pct
        height = 1.px
        margin = Margin((baselineHeight /2)-1.px, 1.px) // 8px 1px
        declarations["*margin"] = "-5px 0px 5px" // IE
        overflow = Overflow.hidden
        backgroundColor = top
        borderBottom = Border(1.px, BorderStyle.solid, bottom)
    }

    // Button backgrounds
    override fun CssBuilder.buttonBackground(
        startColor: Color,
        endColor: Color,
        textColor: Color,
        textShadow: String,
    ) {
        // gradientBar will set the background to a pleasing blend of these, to support IE<=9
        gradientBar(startColor, endColor, textColor, textShadow)

        /* Darken IE7 buttons by default so they stand out more given they won't have borders */
        declarations["*backgroundColor"] = endColor

        resetFilter()


        // in these cases the gradient won't cover the background, so we override
        "&:hover, &:focus, &:active, &.active, &.disabled, &[disabled]" {
            color = textColor
            backgroundColor = endColor
            declarations["*background-color"] = endColor.darken(5)
        }

        // IE 7 + 8 can't handle box-shadow to show active, so we darken a bit ourselves
        "&:active &.active" {
            backgroundColor = Color("${endColor.darken(10)} e(\"\\9\")")
        }
    }

    /**
     * Navbar vertical align.
     * Vertically center elements in the navbar.
     * Example: an element has a height of 30px, so write out `.navbarVerticalAlign(30px);` 
     * to calculate the appropriate top margin.
     */
    override fun CssBuilder.navbarVerticalAlign(
        elementHeight: LinearDimension,
        navbarHeight: LinearDimension,
    ) {
        marginTop = (navbarHeight - elementHeight) / 2
    }
    //endregion
    
    
    //region Grid system
    
    /** Centered container element */
    override fun CssBuilder.containerFixed() {
        marginRight = LinearDimension.auto
        marginLeft = LinearDimension.auto
        clearfix()
    }

    /** Table columns */
    override fun CssBuilder.tableColumns(
        columnSpan: Int,
        vars: Styles.Vars,
        gridColumnWidth: LinearDimension,
        gridGutterWidth: LinearDimension
    ) {
        float = Float.none
        // undo default grid column styles
        width = ((gridColumnWidth) * columnSpan) + (gridGutterWidth * (columnSpan-1))-16.px
        // 16 is total padding on left and right of table cells
        marginLeft = 0.px // undo default grid column styles
    }

    /**
     * Make a Grid.
     * Use .makeRow and .makeColumn to assign semantic layouts grid system behavior
     */
    override fun CssBuilder.makeRow(
        vars: Styles.Vars,
        gridGutterWidth: LinearDimension
    ) {
        marginLeft = gridGutterWidth * -1
        clearfix()
    }

    override fun CssBuilder.makeColumn(
        columns: Int,
        offset: Int,
        vars: Styles.Vars,
        gridColumnWidth: LinearDimension,
        gridGutterWidth: LinearDimension,
    ) {
        float = Float.left
        marginLeft = (gridColumnWidth * offset) + (gridGutterWidth * (offset - 1)) + (gridGutterWidth * 2)
        width = (gridColumnWidth * columns) + (gridGutterWidth * (columns - 1))
    }

    override fun CssBuilder.gridCore(
        vars: Styles.Vars,
        gridColumnWidth: LinearDimension,
        gridGutterWidth: LinearDimension,
        gridColumns: Int,
        builder: Mixins.GridCore.() -> Unit
    ){

        val core = GridCoreImpl(gridColumnWidth, gridGutterWidth)
        core.builder()

        rule("[class*=\"span\"]") {
            float = Float.left
            minHeight = 1.px
            // prevent collapsing columns
            marginLeft = gridGutterWidth
        }

// set the container width, and override it for fixed navbars in media queries
        ".container .navbar-static-top .container .navbar-fixed-top .container .navbar-fixed-bottom .container" {
            with(core) { span(gridColumns) }
        }

        with(core) {
            // generate .spanx and .offsetx
            spanX (gridColumns)
            offsetX (gridColumns);
        }
    }

    class GridCoreImpl @PublishedApi internal constructor(
        val gridColumnWidth: LinearDimension,
        val gridGutterWidth: LinearDimension,
    ) : Mixins.GridCore {
        fun CssBuilder.spanX(index: Int) {
            if (index != 0) {
                ".span@$index" { span(index) }
                spanX(index-1) // recurse
            }
        }

        fun CssBuilder.offsetX(index:Int) {
            if (index > 0) {
                ".offset@$index" {
                    offset(index)
                    offsetX(index - 1) //recurse
                }
            }
        }

        fun CssBuilder.offset (columns: Int) {
            marginLeft = (gridColumnWidth * columns) + (gridGutterWidth * (columns + 1))
        }

        fun CssBuilder.span (columns: Int) {
            width = (gridColumnWidth * columns) + (gridGutterWidth * (columns-1))
        }

        fun CssBuilder.row () {
            marginLeft = gridGutterWidth * -1
            clearfix()
        }


    }


    override fun CssBuilder.gridFluid(
        vars: Styles.Vars,
        fluidGridColumnWidth: LinearDimension,
        fluidGridGutterWidth: LinearDimension,
        gridColumns: Int,
        gridRowWidth: LinearDimension,
        builder: Mixins.GridFluid.() -> Unit
    ){
        val fluid = GridFluidImpl(fluidGridColumnWidth, fluidGridGutterWidth, gridRowWidth)
        fluid.builder()

        ".row-fluid" {
            width = 100.pct
            clearfix()

            "[class*=\"span\"]" {
                inputBlockLevel()
                float = Float.left
                marginLeft = fluidGridGutterWidth
                declarations["*marginLeft"] = "$fluidGridGutterWidth-(.5 / $gridRowWidth * 100 * 1%)"
            }
            "[class*=\"span\"]:first-child" {
                marginLeft = 0.px
            }

            // Space grid-sized controls properly if multiple per line
            ".controls-row [class*=\"span\"] + [class*=\"span\"]" {
                marginLeft = fluidGridGutterWidth
            }

            // generate .spanX and .offsetX
            with(fluid) {
                spanX(gridColumns);
                offsetX (gridColumns);
            }
        }
    }

    class GridFluidImpl(
        val fluidGridColumnWidth: LinearDimension,
        val fluidGridGutterWidth: LinearDimension,
        val gridRowWidth: LinearDimension,
    ) : Mixins.GridFluid {
        fun CssBuilder.spanX(index: Int) {
            if (index>0) {
                ".span@$index" { span(index) }
                spanX(index-1) // recurse
            }
        }

        fun CssBuilder.offsetX(index: Int){
            if(index>0) {
                ".offset@$index" { offset(index) }
                ".offset@$index:first-child" { offsetFirstChild(index) }
                offsetX(index-1) // recurse
            }
        }

    fun CssBuilder.offset(columns: Int) {
        marginLeft = (fluidGridColumnWidth * columns) + (fluidGridGutterWidth * (columns-1)) + (fluidGridGutterWidth*2)
        declarations["*marginLeft"] = "calc((@fluidGridColumnWidth * @columns) + (@fluidGridGutterWidth * (${columns - 1})) - (.5 / $gridRowWidth * 100 * 1%) + ($fluidGridGutterWidth*2) - (.5 / $gridRowWidth * 100 * 1%))"
    }

    fun CssBuilder.offsetFirstChild (columns: Int) {
        marginLeft = (fluidGridColumnWidth * columns) + (fluidGridGutterWidth * (columns-1)) + (fluidGridGutterWidth)
        declarations["*marginLeft"] = "calc((@fluidGridColumnWidth * @columns) + (@fluidGridGutterWidth * (${columns - 1})) - (.5 / $gridRowWidth * 100 * 1%) + ($fluidGridGutterWidth) - (.5 / $gridRowWidth * 100 * 1%))"
    }

    fun CssBuilder.span(columns: Int) {
        width = (fluidGridColumnWidth * columns) + (fluidGridGutterWidth * (columns-1))
        declarations["*width"] ="calc(($fluidGridColumnWidth * $columns) + ($fluidGridGutterWidth * (${columns - 1})) - (.5 / @gridRowWidth * 100 * 1%))"
    }


    }

    override fun CssBuilder.gridInput(
        vars: Styles.Vars,
        gridColumnWidth: LinearDimension,
        gridGutterWidth: LinearDimension,
        gridColumns: Int,
        builder: Mixins.GridInput.() -> Unit
    ){
        val input = GridInputImpl(gridColumnWidth, gridGutterWidth)
        input.builder()

        "input, textarea, .uneditable-input" {
            marginLeft = 0.px
        }

        ".controls-row [class*=\"span\"] + [class*=\"span\"]" {
            marginLeft = gridGutterWidth
        }

        with(input) {
            spanX(gridColumns)
        }
    }

    class GridInputImpl(
        val gridColumnWidth: LinearDimension,
        val gridGutterWidth: LinearDimension,
    ) : Mixins.GridInput {
        fun CssBuilder.spanX(index:Int) {
            if(index>0) {
                "input.span@${index}, textarea.span@${index}, .uneditable-input.span@${index}" {
                    span(index)
                }
                spanX(index - 1)
            }
        }

        fun CssBuilder.span(columns: Int) {
            width = ((gridColumnWidth) * columns) + (gridGutterWidth * (columns-1))-14.px
        }

    }
    

        /*
    

        fun CssBuilder.input(gridColumnWidth, gridGutterWidth) {
    
        .spanX (index) when (index > 0px) {
        input.span@{index}, textarea.span@{index}, .uneditable-input.span@{index} { .span(index);
        }
        mixins.spanX(index-1)
        }
        .spanX (0px) {}
    
        fun CssBuilder.span(columns) {
        width = ((gridColumnWidth) * columns) + (gridGutterWidth * (columns-1))-14
        }
    
        rule("    input textarea .uneditable-input") {
        marginLeft = 0.px // override margin-left from core grid system
        }
    
        // Space grid-sized controls properly if multiple per line
        .controls-row [class*="span"] + [class*="span"] {
        marginLeft = gridGutterWidth
        }
    
        // generate .spanX
        .spanX (gridColumns);
    
        }
        }
        */
}
