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


from django.urls import re_path

from gbpui.panels.application_policy import views

urlpatterns = [
    re_path(r'^$', views.IndexView.as_view(), name='index'),
    re_path(r'^addpolicy_rule_set$', views.AddPolicyRuleSetView.as_view(),
        name='addpolicy_rule_set'),
    re_path(r'^addpolicyrule$', views.AddPolicyRuleView.as_view(),
        name='addpolicyrule'),
    re_path(r'^addpolicyclassifier$', views.AddPolicyClassifierView.as_view(),
        name='addpolicyclassifier'),
    re_path(r'^addpolicyaction$', views.AddPolicyActionView.as_view(),
        name='addpolicyaction'),
    re_path(r'^updatepolicy_rule_set/(?P<policy_rule_set_id>[^/]+)/$',
        views.UpdatePolicyRuleSetView.as_view(), name='updatepolicy_rule_set'),
    re_path(r'^updatepolicyrule/(?P<policyrule_id>[^/]+)/$',
        views.UpdatePolicyRuleView.as_view(), name='updatepolicyrule'),
    re_path(r'^updatepolicyclassifier/(?P<policyclassifier_id>[^/]+)/$',
        views.UpdatePolicyClassifierView.as_view(),
        name='updatepolicyclassifier'),
    re_path(r'^updatepolicyaction/(?P<policyaction_id>[^/]+)/$',
        views.UpdatePolicyActionView.as_view(),
        name='updatepolicyaction'),
    re_path(r'^policyrule/(?P<policyrule_id>[^/]+)/$',
        views.PolicyRuleDetailsView.as_view(), name='policyruledetails'),
    re_path(r'^policyclassifier/(?P<policyclassifier_id>[^/]+)/$',
        views.PolicyClassifierDetailsView.as_view(),
        name='policyclassifierdetails'),
    re_path(r'^policyaction/(?P<policyaction_id>[^/]+)/$',
        views.PolicyActionDetailsView.as_view(),
        name='policyactiondetails'),
    re_path(r'^policy_rule_set/(?P<policy_rule_set_id>[^/]+)/$',
        views.PolicyRuleSetDetailsView.as_view(),
        name='policy_rule_set_details'),
]
