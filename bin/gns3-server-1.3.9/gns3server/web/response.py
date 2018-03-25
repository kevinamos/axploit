# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 GNS3 Technologies Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import json
import jsonschema
import aiohttp.web
import logging
import sys
import jinja2

from ..version import __version__

log = logging.getLogger(__name__)
renderer = jinja2.Environment(loader=jinja2.PackageLoader('gns3server', 'templates'))


class Response(aiohttp.web.Response):

    def __init__(self, request=None, route=None, output_schema=None, headers={}, **kwargs):

        self._route = route
        self._output_schema = output_schema
        self._request = request
        headers['X-Route'] = self._route
        headers['Server'] = "Python/{0[0]}.{0[1]} GNS3/{1}".format(sys.version_info, __version__)
        super().__init__(headers=headers, **kwargs)

    def start(self, request):
        if log.getEffectiveLevel() == logging.DEBUG:
            log.info("%s %s", request.method, request.path_qs)
            log.debug("%s", dict(request.headers))
            if isinstance(request.json, dict):
                log.debug("%s", request.json)
            log.info("Response: %d %s", self.status, self.reason)
            log.debug(dict(self.headers))
            if hasattr(self, 'body') and self.body is not None and self.headers["CONTENT-TYPE"] == "application/json":
                log.debug(json.loads(self.body.decode('utf-8')))
        return super().start(request)

    def html(self, answer):
        """
        Set the response content type to text/html and serialize
        the content.

        :param anwser The response as a Python object
        """

        self.content_type = "text/html"
        self.body = answer.encode('utf-8')

    def template(self, template_filename, **kwargs):
        """
        Render a template

        :params template: Template name
        :params kwargs: Template parameters
        """
        template = renderer.get_template(template_filename)
        kwargs["gns3_version"] = __version__
        kwargs["gns3_host"] = self._request.host
        self.html(template.render(**kwargs))

    def json(self, answer):
        """
        Set the response content type to application/json and serialize
        the content.

        :param anwser The response as a Python object
        """

        self.content_type = "application/json"
        if hasattr(answer, '__json__'):
            answer = answer.__json__()
        if self._output_schema is not None:
            try:
                jsonschema.validate(answer, self._output_schema)
            except jsonschema.ValidationError as e:
                log.error("Invalid output query. JSON schema error: {}".format(e.message))
                raise aiohttp.web.HTTPBadRequest(text="{}".format(e))
        self.body = json.dumps(answer, indent=4, sort_keys=True).encode('utf-8')

    def redirect(self, url):
        """
        Redirect to url

        :params url: Redirection URL
        """
        raise aiohttp.web.HTTPFound(url)
