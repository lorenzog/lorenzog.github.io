# Welcome

I'm Lorenzo and I'm a technologist. I like to work on interesting problems.

This is a place where I write down thoughts on hacking, beauty, and technology.



{% for tag in site.tags %}
  Name: {{ tag | first }},
  count: {{ tag | last | size}}
{% endfor %}

