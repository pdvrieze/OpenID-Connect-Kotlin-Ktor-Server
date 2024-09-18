package io.github.pdvrieze.openid.web.style

import kotlinx.css.CssBuilder
import kotlinx.css.CssProperty
import kotlinx.css.LinearDimension
import kotlinx.css.Rule
import kotlinx.css.RuleContainer
import kotlinx.css.RuleSet
import kotlinx.css.StyledElement

var StyledElement.zoom: Double by CssProperty()

fun CssBuilder.borderWidth(vert: LinearDimension, horiz: LinearDimension) {
    declarations["border-width"] = "$vert $horiz"
}

fun CssBuilder.borderWidth(top: LinearDimension, horiz: LinearDimension, bottom: LinearDimension) {
    declarations["border-width"] = "$top $horiz $bottom"
}

fun CssBuilder.borderWidth(top: LinearDimension, right: LinearDimension, bottom: LinearDimension, left: LinearDimension) {
    declarations["border-width"] = "$top $right $bottom $left"
}

fun RuleContainer.ruleOf(vararg selectors: String, block: RuleSet): Rule {
    return rule(selectors.joinToString(), block)
}

fun RuleContainer.ruleOf(vararg selectors: String, passStaticClassesToParent: Boolean, repeatable: Boolean = false, block: RuleSet): Rule {
    return rule(selectors.joinToString(), passStaticClassesToParent, repeatable, block)
}

fun RuleContainer.ruleOf(vararg selectors: String, passStaticClassesToParent: Boolean, repeatable: Boolean = false, css: CssBuilder): Rule {
    return rule(selectors.joinToString(), passStaticClassesToParent, repeatable, css)
}
