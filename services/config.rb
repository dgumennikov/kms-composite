
coreo_aws_rule "kms-inventory" do
  action :define
  service :kms
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "KMS Inventory"
  description "This rule performs an inventory on all kms objects in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["keys"]
  audit_objects ["object.keys.key_id"]
  operators ["=~"]
  raise_when [//]
  id_map "object.keys.key_id"
end

coreo_aws_rule "kms-key-rotates" do
  action :define
  service :kms
  link "http://kb.cloudcoreo.com/mydoc_kms-key-rotates.html"
  include_violations_in_count true
  display_name "Verify rotation for customer created CMKs is enabled"
  description "AWS Key Management Service (KMS) allows customers to rotate the backing key which is key material stored within the KMS which is tied to the key ID of the Customer Created customer master key (CMK). It is the backing key that is used to perform cryptographic operations such as encryption and decryption. Automated key rotation currently retains all prior backing keys so that decryption of encrypted data can take place transparently."
  category "Audit"
  suggested_action "It is recommended that CMK key rotation be enabled."
  level "Medium"
  meta_cis_id "2.8"
  meta_cis_scored "true"
  meta_cis_level "2"
  objectives ["keys", "key_rotation_status"]
  call_modifiers [{}, {:key_id => "object.keys.key_id"}]
  audit_objects ["", "key_rotation_enabled"]
  operators ["", "=="]
  raise_when ["", false]
  id_map "modifiers.key_id"
end

coreo_uni_util_variables "kms-planwide" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.kms-planwide.composite_name' => 'PLAN::stack_name'},
                {'COMPOSITE::coreo_uni_util_variables.kms-planwide.plan_name' => 'PLAN::name'},
                {'COMPOSITE::coreo_uni_util_variables.kms-planwide.results' => 'unset'},
                {'GLOBAL::number_violations' => '0'}
            ])
end


coreo_aws_rule_runner "advise-kms" do
  action :run
  rules ${AUDIT_AWS_KMS_ALERT_LIST}
  service :kms
  regions ${AUDIT_AWS_KMS_REGIONS}
end

coreo_uni_util_variables "kms-update-planwide-1" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.kms-planwide.results' => 'COMPOSITE::coreo_aws_rule_runner.advise-kms.report'},
                {'GLOBAL::number_violations' => 'COMPOSITE::coreo_aws_rule_runner.advise-kms.number_violations'},

            ])
end

coreo_uni_util_jsrunner "tags-to-notifiers-array-kms" do
  action :run
  data_type "json"
  provide_composite_access true
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.10.7-9"
               },
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "cloud account name": "PLAN::cloud_account_name",
                "violations": COMPOSITE::coreo_aws_rule_runner.advise-kms.report}'
  function <<-EOH



function setTableAndSuppression() {
  let table;
  let suppression;

  const fs = require('fs');
  const yaml = require('js-yaml');
  try {
      suppression = yaml.safeLoad(fs.readFileSync('./suppression.yaml', 'utf8'));
  } catch (e) {
      console.log("Error reading suppression.yaml file: " , e);
      suppression = {};
  }
  try {
      table = yaml.safeLoad(fs.readFileSync('./table.yaml', 'utf8'));
  } catch (e) {
      console.log("Error reading table.yaml file: ", e);
      table = {};
  }
  coreoExport('table', JSON.stringify(table));
  coreoExport('suppression', JSON.stringify(suppression));

  let alertListToJSON = "${AUDIT_AWS_KMS_ALERT_LIST}";
  let alertListArray = alertListToJSON.replace(/'/g, '"');
  json_input['alert list'] = alertListArray || [];
  json_input['suppression'] = suppression || [];
  json_input['table'] = table || {};
}


setTableAndSuppression();

const JSON_INPUT = json_input;
const NO_OWNER_EMAIL = "${AUDIT_AWS_KMS_ALERT_RECIPIENT}";
const OWNER_TAG = "${AUDIT_AWS_KMS_OWNER_TAG}";
const ALLOW_EMPTY = "${AUDIT_AWS_KMS_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_KMS_SEND_ON}";
const SHOWN_NOT_SORTED_VIOLATIONS_COUNTER = false;

const SETTINGS = { NO_OWNER_EMAIL, OWNER_TAG,
    ALLOW_EMPTY, SEND_ON, SHOWN_NOT_SORTED_VIOLATIONS_COUNTER};

const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditKMS = new CloudCoreoJSRunner(JSON_INPUT, SETTINGS);
const letters = AuditKMS.getLetters();

const newJSONInput = AuditKMS.getSortedJSONForAuditPanel();
coreoExport('JSONReport', JSON.stringify(newJSONInput));
coreoExport('report', JSON.stringify(newJSONInput['violations']));

callback(letters);
  EOH
end

coreo_uni_util_variables "kms-update-planwide-3" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.kms-planwide.results' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-kms.JSONReport'},
                {'COMPOSITE::coreo_aws_rule_runner.advise-kms.report' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-kms.report'},
                {'GLOBAL::table' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-kms.table'}
            ])
end

coreo_uni_util_jsrunner "tags-rollup-kms" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-kms.return'
  function <<-EOH
const notifiers = json_input;

function setTextRollup() {
    let emailText = '';
    let numberOfViolations = 0;
    notifiers.forEach(notifier => {
        const hasEmail = notifier['endpoint']['to'].length;
        if(hasEmail) {
            numberOfViolations += parseInt(notifier['num_violations']);
            emailText += "recipient: " + notifier['endpoint']['to'] + " - " + "Violations: " + notifier['num_violations'] + "\\n";
        }
    });

    textRollup += 'Number of Violating Cloud Objects: ' + numberOfViolations + "\\n";
    textRollup += 'Rollup' + "\\n";
    textRollup += emailText;
}


let textRollup = '';
setTextRollup();

callback(textRollup);
  EOH
end

coreo_uni_util_notify "advise-kms-to-tag-values" do
  action((("${AUDIT_AWS_KMS_ALERT_RECIPIENT}".length > 0)) ? :notify : :nothing)
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-kms.return'
end

coreo_uni_util_notify "advise-kms-rollup" do
  action((("${AUDIT_AWS_KMS_ALERT_RECIPIENT}".length > 0) and (! "${AUDIT_AWS_KMS_OWNER_TAG}".eql?("NOT_A_TAG"))) ? :notify : :nothing)
  type 'email'
  allow_empty ${AUDIT_AWS_KMS_ALLOW_EMPTY}
  send_on '${AUDIT_AWS_KMS_SEND_ON}'
  payload '
composite name: PLAN::stack_name
plan name: PLAN::name
COMPOSITE::coreo_uni_util_jsrunner.tags-rollup-kms.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_KMS_ALERT_RECIPIENT}', :subject => 'CloudCoreo kms rule results on PLAN::stack_name :: PLAN::name'
  })
end
