# -*- coding: utf-8 -*-
"""
Recipe
======
An ordered list of (operation, args) steps that gets "baked" against an
input, exactly like CyberChef's recipe area (src/core/Recipe.mjs). Each
step's output becomes the next step's input. If a step raises, baking
stops there and the partial output + error are reported back so the user
can see exactly which step in the chain misbehaved.
"""

from .dish import to_bytes, to_str
from .logger import log


class RecipeStepError(Exception):
    def __init__(self, step_index, operation_name, original_exc):
        self.step_index = step_index
        self.operation_name = operation_name
        self.original_exc = original_exc
        super(RecipeStepError, self).__init__(
            "Step %d (%s): %s" % (step_index + 1, operation_name, original_exc)
        )


class BakeResult(object):
    def __init__(self, output, error=None, last_good_step=-1):
        self.output = output          # bytes - best output we could produce
        self.error = error            # RecipeStepError or None
        self.last_good_step = last_good_step  # index of last step that succeeded


class Recipe(object):
    def __init__(self):
        self.steps = []  # list of (operation_instance, args_list)

    def add_step(self, operation, args=None):
        self.steps.append([operation, args if args is not None else operation.args])

    def remove_step(self, index):
        if 0 <= index < len(self.steps):
            self.steps.pop(index)

    def move_step(self, index, delta):
        new_index = index + delta
        if 0 <= new_index < len(self.steps) and 0 <= index < len(self.steps):
            self.steps[index], self.steps[new_index] = self.steps[new_index], self.steps[index]
            return new_index
        return index

    def clear(self):
        self.steps = []

    def bake(self, input_data):
        data = to_bytes(input_data)
        last_good_step = -1
        for i, (operation, args) in enumerate(self.steps):
            try:
                result = operation.run(data, args)
                new_data = to_bytes(result)
                log.info("Step %d '%s' -> %s", i + 1, operation.name, to_str(new_data)[:300])
                data = new_data
                last_good_step = i
            except Exception as exc:  # noqa: BLE001 - surface any op failure to UI
                log.error("Step %d '%s' FAILED: %s", i + 1, operation.name, exc)
                return BakeResult(data, RecipeStepError(i, operation.name, exc), last_good_step)
        return BakeResult(data, None, last_good_step)
