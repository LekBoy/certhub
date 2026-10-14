from django import template

register = template.Library()


@register.filter
def startswith(value, prefix):
    return str(value).startswith(str(prefix))
