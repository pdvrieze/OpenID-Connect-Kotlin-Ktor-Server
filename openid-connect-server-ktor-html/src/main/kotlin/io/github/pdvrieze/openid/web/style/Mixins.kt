package io.github.pdvrieze.openid.web.style

import io.github.pdvrieze.openid.web.style.default.DefaultMixins
import io.github.pdvrieze.openid.web.style.default.DefaultStyles
import kotlinx.css.BackgroundClip
import kotlinx.css.BoxSizing
import kotlinx.css.Color
import kotlinx.css.CssBuilder
import kotlinx.css.FontWeight
import kotlinx.css.Hyphens
import kotlinx.css.LinearDimension
import kotlinx.css.Resize
import kotlinx.css.UserSelect
import kotlinx.css.Visibility
import kotlinx.css.pct
import kotlinx.css.properties.Angle
import kotlinx.css.properties.BoxShadow
import kotlinx.css.properties.BoxShadowInset
import kotlinx.css.properties.BoxShadows
import kotlinx.css.properties.LineHeight
import kotlinx.css.properties.Time
import kotlinx.css.properties.Timing
import kotlinx.css.properties.deg
import kotlinx.css.properties.lh
import kotlinx.css.px

interface Mixins {
    val mixins: DefaultMixins

    /**
     * For clearing floats like a boss h5bp.com/q
     */
    fun CssBuilder.clearfix()

    /** Webkit-style focus */
    fun CssBuilder.tabFocus()

    /** Center-align a block level element */
    fun CssBuilder.centerBlock()

    /** IE7 inline-block */
    fun CssBuilder.ie7InlineBlock()

    /**
     * IE7 likes to collapse whitespace on either side of the inline-block elements.
     * Ems because we're attempting to match the width of a space character. Left
     * version is for form buttons, which typically come after other elements, and
     * right version is for icons, which come before. Applying both is ok, but it will
     * mean that space between those elements will be 0.6.em (~2 space characters) in IE7 // instead of the 1 space in other browsers.
     */
    fun CssBuilder.ie7RestoreLeftWhitespace()
    fun CssBuilder.ie7RestoreRightWhitespace()

    /** Sizing shortcuts */
    fun CssBuilder.size(height: LinearDimension, width: LinearDimension)
    fun CssBuilder.square(size: LinearDimension)

    /** Placeholder text */
    fun CssBuilder.placeholder(color: Color = DefaultStyles.vars.placeholderText)

    /**
     * Text overflow.
     *
     * Requires inline-block or block for proper styling
     */
    fun CssBuilder.textOverflow()

    /**
     * CSS image replacement.
     * Source: https://github.com/h5bp/html5-boilerplate/commit/aa0396eae757
     */
    fun CssBuilder.hideText()
    fun CssBuilder.fontFamilySerif(vars: Styles.Vars = DefaultStyles.DefaultVars)
    fun CssBuilder.fontFamilySansSerif(vars: Styles.Vars = DefaultStyles.DefaultVars)
    fun CssBuilder.fontFamilyMonospace(vars: Styles.Vars = DefaultStyles.DefaultVars)
    fun CssBuilder.fontShorthand(
        size: LinearDimension = DefaultStyles.DefaultVars.baseFontSize,
        weight: FontWeight = FontWeight.normal,
        lineHeight: LineHeight = DefaultStyles.DefaultVars.baseLineHeight.lh,
    )

    fun CssBuilder.serif(
        vars: Styles.Vars = DefaultStyles.DefaultVars,
        weight: FontWeight = FontWeight.normal,
        size: LinearDimension = vars.baseFontSize,
        lineHeight: LineHeight = vars.baseLineHeight.lh,
    )

    fun CssBuilder.sansSerif(
        vars: Styles.Vars = DefaultStyles.DefaultVars,
        weight: FontWeight = FontWeight.normal,
        size: LinearDimension = vars.baseFontSize,
        lineHeight: LineHeight = vars.baseLineHeight.lh,
    )

    fun CssBuilder.monospace(
        vars: Styles.Vars = DefaultStyles.DefaultVars,
        weight: FontWeight = FontWeight.normal,
        size: LinearDimension = vars.baseFontSize,
        lineHeight: LineHeight = vars.baseLineHeight.lh,
    )

    /** Block level inputs */
    fun CssBuilder.inputBlockLevel(inputHeight: LinearDimension = DefaultStyles.DefaultVars.inputHeight)
    fun CssBuilder.formFieldState(
        textColor: Color = Color("#555"),
        borderColor: Color = Color("#ccc"),
        backgroundColor: Color = Color("#f5f5f5")
    )

    /** Border Radius */
    fun CssBuilder.borderRadius(radius: LinearDimension)
    fun CssBuilder.borderRadius(topLeft: LinearDimension, topRight: LinearDimension, bottomRight: LinearDimension, bottomLeft: LinearDimension) {
        borderTopLeftRadius(topLeft)
        borderTopRightRadius(topRight)
        borderBottomLeftRadius(bottomLeft)
        borderBottomRightRadius(bottomRight)
    }

    // Single Corner Border Radius
    fun CssBuilder.borderTopLeftRadius(radius: LinearDimension)
    fun CssBuilder.borderTopRightRadius(radius: LinearDimension)
    fun CssBuilder.borderBottomRightRadius(radius: LinearDimension)
    fun CssBuilder.borderBottomLeftRadius(radius: LinearDimension)

    // Single Side Border Radius
    fun CssBuilder.borderTopRadius(radius: LinearDimension)
    fun CssBuilder.borderRightRadius(radius: LinearDimension)
    fun CssBuilder.borderBottomRadius(radius: LinearDimension)
    fun CssBuilder.borderLeftRadius(radius: LinearDimension)

    fun CssBuilder.boxShadow(builder: BoxShadows.() -> Unit) {
        boxShadow(BoxShadows().apply(builder))
    }

    fun CssBuilder.boxShadow(
        color: Color,
        offsetX: LinearDimension = 0.px,
        offsetY: LinearDimension = 0.px,
        blurRadius: LinearDimension = 0.px,
        spreadRadius: LinearDimension = 0.px,
    ) {
        boxShadow(BoxShadows().apply {  this+= BoxShadow(color, offsetX, offsetY, blurRadius, spreadRadius) })
    }

    fun CssBuilder.boxShadowInset(
        color: Color,
        offsetX: LinearDimension = 0.px,
        offsetY: LinearDimension = 0.px,
        blurRadius: LinearDimension = 0.px,
        spreadRadius: LinearDimension = 0.px,
    ) {
        boxShadow(BoxShadows().apply {  this+= BoxShadowInset(color, offsetX, offsetY, blurRadius, spreadRadius) })
    }

    fun CssBuilder.boxShadow(
        offsetX: LinearDimension,
        offsetY: LinearDimension,
        blurRadius: LinearDimension,
        color: Color,
        spreadRadius: LinearDimension = 0.px,
    ) {
        boxShadow(BoxShadows().apply {  this+= BoxShadow(color, offsetX, offsetY, blurRadius, spreadRadius) })
    }

    fun CssBuilder.boxShadowInset(
        offsetX: LinearDimension,
        offsetY: LinearDimension,
        blurRadius: LinearDimension,
        color: Color,
        spreadRadius: LinearDimension = 0.px,
    ) {
        boxShadow(BoxShadows().apply {  this+= BoxShadowInset(color, offsetX, offsetY, blurRadius, spreadRadius) })
    }

    // Drop shadows
    fun CssBuilder.boxShadow(shadow: BoxShadows)

    // Transitions
    fun CssBuilder.transition(transition: String)
    fun CssBuilder.transition(property: String, duration: Time, timing: Timing)
    fun CssBuilder.transitionDelay(transitionDelay: Time)
    fun CssBuilder.transitionDuration(transitionDuration: Time)

    // Transformations
    fun CssBuilder.rotate(degrees: Angle)
    fun CssBuilder.scale(ratio: Double)
    fun CssBuilder.translateM(x: LinearDimension, y: LinearDimension)
    fun CssBuilder.skew(x: Angle, y: Angle)
    fun CssBuilder.translate3d(x: LinearDimension, y: LinearDimension, z: LinearDimension)

    /**
     * Backface visibility
     * Prevent browsers from flickering when using CSS 3D transforms.
     * Default value is `visible`, but can be changed to `hidden
     * See git pull https://github.com/dannykeane/bootstrap.git backface-visibility for examples
     */
    fun CssBuilder.backfaceVisibility(visibility: Visibility)

    /**
     * Background clipping
     * Heads up: FF 3.6 and under need "padding" instead of "padding-box"
     */
    fun CssBuilder.backgroundClip(clip: BackgroundClip)

    /** Background sizing */
    fun CssBuilder.backgroundSize(size: String)

    /** Box sizing */
    fun CssBuilder.boxSizing(boxmodel: BoxSizing)

    /**
     * User select
     * For selecting text on the page
     */
    fun CssBuilder.userSelect(select: UserSelect)

    /** Resize anything */
    fun CssBuilder.resizable(direction: Resize)

    /** CSS3 Content Columns */
    fun CssBuilder.contentColumns(columnCount: Int, columnGap: LinearDimension = DefaultStyles.DefaultVars.gridGutterWidth)

    /**
     * Overload for automatic column count (based upon sizes)
     */
    fun CssBuilder.autoContentColumns(columnGap: LinearDimension = DefaultStyles.DefaultVars.gridGutterWidth)

    // Optional hyphenation
    fun CssBuilder.hyphens(mode: Hyphens = Hyphens.auto)

    // Opacity
    fun CssBuilder.opacity(opacity: Number)

    // Add an alphatransparency value to any background or border color (via Elyse Holladay)
    fun CssBuilder.translucentBackground(color: Color = DefaultStyles.DefaultVars.white, alpha: Double = 1.0)
    fun CssBuilder.translucentBorder(color: Color = DefaultStyles.DefaultVars.white, alpha: Double =1.0)

    /** Gradient Bar Colors for buttons and alerts */
    fun CssBuilder.gradientBar(
        primaryColor: Color,
        secondaryColor: Color,
        textColor: Color = Color("#fff"),
        textShadow: String = "0px -1px 0px rgba(0,0,0,.25)",
    )

    fun CssBuilder.gradientHorizontal(startColor: Color = Color("#555"), endColor: Color = Color("#333"))
    fun CssBuilder.gradientVertical(startColor: Color = Color("#555"), endColor: Color = Color("#333"))
    fun CssBuilder.gradientDirectional(
        startColor: Color = Color("#555"),
        endColor: Color = Color("#333"),
        deg: Angle = 45.deg,
    )

    fun CssBuilder.gradientHorizontalThreeColors(
        startColor: Color = Color("#00b3ee"),
        midColor: Color = Color("#7a43b6"),
        colorStop: LinearDimension = 50.pct,
        endColor: Color = Color("#c3325f")
    )

    fun CssBuilder.gradientVerticalThreeColors(
        startColor: Color = Color("#00b3ee"),
        midColor: Color = Color("#7a43b6"),
        colorStop: LinearDimension = 50.pct,
        endColor: Color = Color("#c3325f")
    )

    fun CssBuilder.gradientRadial(innerColor: Color = Color("#555"), outerColor: Color = Color("#333"))
    fun CssBuilder.gradientStriped(color: Color = Color("#555"), angle: Angle = 45.deg)

    /** Reset filters for IE */
    fun CssBuilder.resetFilter()

    /**
     * Horizontal dividers
     * Dividers (basically an hr) within dropdowns and nav lists
     */
    fun CssBuilder.navDivider(
        top: Color = Color("#e5e5e5"),
        bottom: Color = DefaultStyles.DefaultVars.white,
        baselineHeight: LinearDimension = DefaultStyles.DefaultVars.baseLineHeight,
    )

    // Button backgrounds
    fun CssBuilder.buttonBackground(
        startColor: Color,
        endColor: Color,
        textColor: Color = Color("#fff"),
        textShadow: String = "0px -1px 0px rgba(0,0,0,.25)",
    )

    /**
     * Navbar vertical align.
     * Vertically center elements in the navbar.
     * Example: an element has a height of 30px, so write out `.navbarVerticalAlign(30px);`
     * to calculate the appropriate top margin.
     */
    fun CssBuilder.navbarVerticalAlign(
        elementHeight: LinearDimension,
        navbarHeight: LinearDimension = DefaultStyles.DefaultVars.navbarHeight,
    )

    /** Centered container element */
    fun CssBuilder.containerFixed()

    /** Table columns */
    fun CssBuilder.tableColumns(
        columnSpan: Int = 1,
        vars: Styles.Vars = DefaultStyles.DefaultVars,
        gridColumnWidth: LinearDimension = vars.gridColumnWidth,
        gridGutterWidth: LinearDimension = vars.gridGutterWidth
    )

    /**
     * Make a Grid.
     * Use .makeRow and .makeColumn to assign semantic layouts grid system behavior
     */
    fun CssBuilder.makeRow(
        vars: Styles.Vars = DefaultStyles.DefaultVars,
        gridGutterWidth: LinearDimension = vars.gridGutterWidth
    )

    fun CssBuilder.makeColumn(
        columns: Int = 1,
        offset: Int = 0,
        vars: Styles.Vars = DefaultStyles.DefaultVars,
        gridColumnWidth: LinearDimension = vars.gridColumnWidth,
        gridGutterWidth: LinearDimension = vars.gridGutterWidth,
    )

    fun CssBuilder.gridCore(gridColumnWidth: LinearDimension, gridGutterWidth: LinearDimension, builder: GridCore.() -> Unit = {}): Unit {
        gridCore(DefaultStyles.DefaultVars, gridColumnWidth, gridGutterWidth, builder = builder)
    }

    fun CssBuilder.gridCore(
        vars: Styles.Vars = DefaultStyles.DefaultVars,
        gridColumnWidth: LinearDimension = vars.gridColumnWidth,
        gridGutterWidth: LinearDimension = vars.gridGutterWidth,
        gridColumns: Int = vars.gridColumns,
        builder: GridCore.() -> Unit
    )

    fun CssBuilder.gridFluid(gridColumnWidth: LinearDimension, gridGutterWidth: LinearDimension, builder: GridFluid.() -> Unit = {}): Unit {
        gridFluid(DefaultStyles.DefaultVars, gridColumnWidth, gridGutterWidth, builder = builder)
    }

    fun CssBuilder.gridFluid(
        vars: Styles.Vars = DefaultStyles.DefaultVars,
        fluidGridColumnWidth: LinearDimension = vars.fluidGridColumnWidth,
        fluidGridGutterWidth: LinearDimension = vars.fluidGridGutterWidth,
        gridColumns: Int = vars.gridColumns,
        gridRowWidth: LinearDimension = vars.gridRowWidth,
        builder: GridFluid.() -> Unit
    )

    fun CssBuilder.gridInput(gridColumnWidth: LinearDimension, gridGutterWidth: LinearDimension, builder: GridInput.() -> Unit = {}): Unit {
        gridInput(DefaultStyles.DefaultVars, gridColumnWidth, gridGutterWidth, builder = builder)
    }

    fun CssBuilder.gridInput(
        vars: Styles.Vars = DefaultStyles.DefaultVars,
        gridColumnWidth: LinearDimension = vars.gridColumnWidth,
        gridGutterWidth: LinearDimension = vars.gridGutterWidth,
        gridColumns: Int = vars.gridColumns,
        builder: GridInput.() -> Unit
    )

    interface GridInput {
        fun CssBuilder.spanX(index: Int)
        fun CssBuilder.span(columns: Int)

    }

    interface GridCore {
        fun CssBuilder.spanX(index: Int)
        fun CssBuilder.offsetX(index: Int)
        fun CssBuilder.offset (columns: Int)
        fun CssBuilder.span (columns: Int)
        fun CssBuilder.row ()
    }

    interface GridFluid {
        fun CssBuilder.spanX(index: Int)
        fun CssBuilder.offsetX(index: Int)
        fun CssBuilder.offset(columns: Int)
        fun CssBuilder.offsetFirstChild (columns: Int)
        fun CssBuilder.span(columns: Int)
    }
}
