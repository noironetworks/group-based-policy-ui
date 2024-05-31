# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from django.urls import reverse
from django.utils.html import format_html
from django.utils.html import format_html_join
from django.utils.safestring import mark_safe

from gbpui import client


def list_column_filter(items):
    if len(items) == 0:
        return ""
    return items


def update_pruleset_attributes(request, prset):
    rules = prset.policy_rules
    url = "horizon:project:application_policy:policyruledetails"
    value = ["<ul>"]
    for rule in rules:
        r = client.policyrule_get(request, rule)
        li = format_html("<li><a href='{}'>{}</a></li>",
                         reverse(url, kwargs={'policyrule_id': r.id}),
                         r.name)
        value.append(li)
    value.append("</ul>")
    value = "".join(value)
    setattr(prset, 'policy_rules', mark_safe(value))  # nosec
    return prset


def update_service_policy_attributes(policy):
    np = policy.network_service_params
    params = ""
    if len(np) > 0:
        tags = []
        for item in np:
            dl = [mark_safe("<dl class='dl-horizontal'>")]  # nosec
            dl.extend(format_html_join('', "<dt>{}<dt><dd>{}</dd>",
                ((k, v) for k, v in list(item.items()))))
            dl.append(mark_safe("</dl>"))  # nosec
            tags.append("".join(dl))
        params = mark_safe("".join(tags))  # nosec
    setattr(policy, 'network_service_params', params)
    return policy


def update_policy_target_attributes(request, pt):
    url = "horizon:project:application_policy:policy_rule_set_details"
    provided = pt.provided_policy_rule_sets
    consumed = pt.consumed_policy_rule_sets
    provided = [client.policy_rule_set_get(request, item) for item in provided]
    consumed = [client.policy_rule_set_get(request, item) for item in consumed]
    p = ["<ul>"]
    li = lambda url, item: (format_html("<li><a href='{}'>{}</a></li>",
        reverse(url, kwargs={'policy_rule_set_id': item.id}), item.name))
    for item in provided:
        p.append(li(url, item))
    p.append("</ul>")
    p = "".join(p)
    c = ["<ul>"]
    for item in consumed:
        c.append(li(url, item))
    c.append("</ul>")
    c = "".join(c)
    consumed = [item.name for item in consumed]
    setattr(pt, 'provided_policy_rule_sets', mark_safe(p))  # nosec
    setattr(pt, 'consumed_policy_rule_sets', mark_safe(c))  # nosec
    l2url = "horizon:project:network_policy:l2policy_details"
    if hasattr(pt, 'l2_policy_id') and pt.l2_policy_id is not None:
        policy = client.l2policy_get(request, pt.l2_policy_id)
        u = reverse(l2url, kwargs={'l2policy_id': policy.id})
        atag = format_html("<a href='{}'>{}</a>", u, policy.name)
        setattr(pt, 'l2_policy_id', atag)
    if hasattr(pt, 'external_segments'):
        exturl = "horizon:project:network_policy:external_connectivity_details"
        value = ["<ul>"]
        li = lambda x: format_html("<li><a href='{}'>{}</a></li>",
            reverse(exturl, kwargs={'external_connectivity_id': x.id}),
            x.name)
        for external_segment in pt.external_segments:
            ext_policy = client.get_externalconnectivity(request,
                external_segment)
            value.append(li(ext_policy))
        value.append("</ul>")
        value = "".join(value)
        setattr(pt, 'external_segments', mark_safe(value))  # nosec
    return pt


def update_policyrule_attributes(request, prule):
    url = "horizon:project:application_policy:policyclassifierdetails"
    classifier_id = prule.policy_classifier_id
    classifier = client.policyclassifier_get(request, classifier_id)
    u = reverse(url, kwargs={'policyclassifier_id': classifier.id})
    tag = format_html("<a href='{}'>{}</a>", u, classifier.name)
    setattr(prule, 'policy_classifier_id', tag)
    actions = prule.policy_actions
    action_url = "horizon:project:application_policy:policyactiondetails"
    ul = [mark_safe("<ul>")]  # nosec
    for a in actions:
        action = client.policyaction_get(request, a)
        u = reverse(action_url, kwargs={'policyaction_id': a})
        li = format_html("<li><a href='%s'>%s</a></li>", u, action.name)
        ul.append(li)
    ul.append(mark_safe("</ul>"))  # nosec
    ultag = "".join(ul)
    setattr(prule, 'policy_actions', mark_safe(ultag))  # nosec
    return prule


def update_policyaction_attributes(request, paction):
    return paction


def update_classifier_attributes(classifiers):
    port_protocol_map = {'21': 'ftp', '25': 'smtp', '53': 'dns',
                        '80': 'http', '443': 'https'}
    if type(classifiers) == list:
        for classifier in classifiers:
            classifier.set_id_as_name_if_empty()
            if classifier.protocol in ['tcp', 'udp'] and classifier.port_range\
                    in port_protocol_map:
                classifier.protocol = port_protocol_map[classifier.port_range]
    else:
        if classifiers.protocol in ['tcp', 'udp'] and classifiers.port_range \
                in port_protocol_map:
            classifiers.protocol = port_protocol_map[classifiers.port_range]
    return classifiers


def update_l3_policy_attributes(request, l3_policy):
    url = "horizon:project:network_policy:external_connectivity_details"
    if bool(l3_policy.external_segments):
        value = [mark_safe("<ul>")]  # nosec
        li = lambda x: format_html("<li><a href='{}'>{}</a> : {}</li>",
            reverse(url, kwargs={'external_connectivity_id': x.id}),
            x.name, l3_policy.external_segments[x.id][0])
        for ec in list(l3_policy.external_segments.keys()):
            external_connectivity = client.get_externalconnectivity(request,
                                                                    ec)
            value.append(li(external_connectivity))
        value.append(mark_safe("</ul>"))  # nosec
        tag = mark_safe("".join(value))  # nosec
    else:
        tag = '-'
    setattr(l3_policy, 'external_segments', tag)
    return l3_policy


def update_nat_pool_attributes(request, nat_pool):
    url = "horizon:project:network_policy:external_connectivity_details"
    id = nat_pool.external_segment_id
    value = [mark_safe("<ul>")]  # nosec
    li = lambda x: format_html("<li><a href='{}'>{}</a></li>",
        reverse(url, kwargs={'external_connectivity_id': x.id}), x.name)
    external_connectivity = client.get_externalconnectivity(request,
                                                                id)
    value.append(li(external_connectivity))
    value.append(mark_safe("</ul>"))  # nosec
    tag = mark_safe("".join(value))  # nosec
    setattr(nat_pool, 'external_segment_id', tag)
    return nat_pool
