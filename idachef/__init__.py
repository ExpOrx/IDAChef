"""
IDAChef - A CyberChef-inspired recipe/operation toolkit embedded in IDA Pro.

Architecture mirrors CyberChef's own layout (see gchq/CyberChef, src/core/):
    core/operation.py   -> base "Operation" class          (cf. src/core/Operation.mjs)
    core/recipe.py      -> "Recipe" chain runner            (cf. src/core/Recipe.mjs)
    core/dish.py         -> data-type conversion helper      (cf. src/core/Dish.mjs)
    operations/*.py      -> individual operations by category (cf. src/core/operations/*.mjs)
    ui/chef_widget.py    -> the dockable IDA widget (recipe list + bake)
"""

__version__ = "1.0.0"
