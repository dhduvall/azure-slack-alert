use chrono::{DateTime, Utc};
use serde::{self, Deserialize, Deserializer};
use std::collections::HashMap;
use std::fmt::Debug;
use uuid::Uuid;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[allow(unused)]
struct ActivityLog {
    schema_id: String,
    data: AlertData,
}

#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
#[allow(unused)]
struct AlertData {
    status: String,
    #[serde(default)]
    properties: HashMap<String, String>,
    context: AlertContext,
}

#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
#[allow(unused)]
struct AlertContext {
    activity_log: InnerActivityLog,
}

#[derive(Deserialize, Debug, Default)]
#[serde(untagged)]
enum InnerActivityLog {
    #[default]
    Dummy,
    SecurityLog(SecurityLog),
    Recommendation(Recommendation),
    ServiceHealth(ServiceHealth),
    ResourceHealth(ResourceHealth),
    Administrative(Administrative),
}

// common fields would use flatten

#[derive(Deserialize, Debug, Default)]
#[serde(default, rename_all = "camelCase")]
#[allow(unused)]
struct ServiceHealth {
    channels: String, // Enum?
    correlation_id: Uuid,
    description: String,
    #[serde(deserialize_with = "deserialize_event_source_service_health")]
    event_source: String, // must be "ServiceHealth"
    event_timestamp: DateTime<Utc>,
    event_data_id: Uuid,
    level: String, // Enum?
    operation_name: String,
    operation_id: Uuid,
    status: String, // Enum?
    subscription_id: Uuid,
    properties: ServiceHealthProperties,
}

#[derive(Deserialize, Debug, Default)]
#[serde(default, rename_all = "camelCase")]
#[allow(unused)]
struct ServiceHealthProperties {
    title: String,
    service: String,
    region: String,
    communication: String,
    incident_type: String, // Enum?
    tracking_id: String,
    impact_start_time: DateTime<Utc>,
    impacted_services: String, // JSON
    default_language_title: String,
    default_language_content: String,
    stage: String, // Enum?
    communication_id: String,
    version: String,
}

#[derive(Deserialize, Debug, Default)]
#[serde(default, rename_all = "camelCase")]
#[allow(unused)]
struct Recommendation {
    #[serde(deserialize_with = "deserialize_event_source_recommendation")]
    event_source: String,
}

#[derive(Deserialize, Debug, Default)]
#[serde(default, rename_all = "camelCase")]
#[allow(unused)]
struct SecurityLog {
    #[serde(deserialize_with = "deserialize_event_source_security_log")]
    event_source: String,
}

#[derive(Deserialize, Debug, Default)]
#[serde(default, rename_all = "camelCase")]
#[allow(unused)]
struct ResourceHealth {
    #[serde(deserialize_with = "deserialize_event_source_resource_health")]
    event_source: String,
}

#[derive(Deserialize, Debug, Default)]
#[serde(default, rename_all = "camelCase")]
#[allow(unused)]
struct Administrative {
    #[serde(deserialize_with = "deserialize_event_source_administrative")]
    event_source: String,
}

fn deserialize_event_source_generic<'de, D>(
    deserializer: D,
    event_source: &str,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let buf = String::deserialize(deserializer)?;
    if buf == event_source {
        Ok(buf)
    } else {
        Err(format!("eventSource is '{buf}', must be '{event_source}'"))
            .map_err(serde::de::Error::custom)
    }
}

fn deserialize_event_source_service_health<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_event_source_generic(deserializer, "ServiceHealth")
}

fn deserialize_event_source_recommendation<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_event_source_generic(deserializer, "Recommendation")
}

fn deserialize_event_source_security_log<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_event_source_generic(deserializer, "SecurityLog")
}

fn deserialize_event_source_resource_health<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_event_source_generic(deserializer, "ResourceHealth")
}

fn deserialize_event_source_administrative<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_event_source_generic(deserializer, "Administrative")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_de_activity_log_service_health() {
        let buf = r#"
            {
              "schemaId": "Microsoft.Insights/activityLogs",
              "data": {
                "status": "Activated",
                "properties": {},
                "context": {
                  "activityLog": {
                    "description": "Active: Virtual Machines - Australia East",
                    "eventSource": "ServiceHealth"
                  }
                }
              }
            }
        "#;

        // Can we deserialize at all?
        let al: ActivityLog = serde_json::from_str(buf).unwrap();
        println!("{:#?}", al);

        // Did it end up as a ServiceHealth log?
        if let InnerActivityLog::ServiceHealth(sh) = al.data.context.activity_log {
            assert_eq!(sh.event_source, "ServiceHealth");
        } else {
            // XXX Can we print the type?  Maybe see https://stackoverflow.com/questions/32710187/how-do-i-get-an-enum-as-a-string
            panic!("Incorrect activity log type");
        }
    }

    #[test]
    fn test_de_service_health() {
        // XXX We'll probably want to pull this from somewhere common.
        let buf = r#"{
          "channels": "Admin",
          "correlationId": "bbac944f-ddc0-4b4c-aa85-cc7dc5d5c1a6",
          "description": "Active: Virtual Machines - Australia East",
          "eventSource": "ServiceHealth",
          "eventTimestamp": "2017-10-18T23:49:25.3736084+00:00",
          "eventDataId": "6fa98c0f-334a-b066-1934-1a4b3d929856",
          "level": "Informational",
          "operationName": "Microsoft.ServiceHealth/incident/action",
          "operationId": "bbac944f-ddc0-4b4c-aa85-cc7dc5d5c1a6",
          "properties": {
            "title": "Virtual Machines - Australia East",
            "service": "Virtual Machines",
            "region": "Australia East",
            "communication": "Starting at 02:48 UTC on 18 Oct 2017 you have been identified as a customer using Virtual Machines in Australia East who may receive errors starting Dv2 Promo and DSv2 Promo Virtual Machines which are in a stopped &quot;deallocated&quot; or suspended state. Customers can still provision Dv1 and Dv2 series Virtual Machines or try deploying Virtual Machines in other regions, as a possible workaround. Engineers have identified a possible fix for the underlying cause, and are exploring implementation options. The next update will be provided as events warrant.",
            "incidentType": "Incident",
            "trackingId": "0NIH-U2O",
            "impactStartTime": "2017-10-18T02:48:00.0000000Z",
            "impactedServices": "[{\"ImpactedRegions\":[{\"RegionName\":\"Australia East\"}],\"ServiceName\":\"Virtual Machines\"}]",
            "defaultLanguageTitle": "Virtual Machines - Australia East",
            "defaultLanguageContent": "Starting at 02:48 UTC on 18 Oct 2017 you have been identified as a customer using Virtual Machines in Australia East who may receive errors starting Dv2 Promo and DSv2 Promo Virtual Machines which are in a stopped &quot;deallocated&quot; or suspended state. Customers can still provision Dv1 and Dv2 series Virtual Machines or try deploying Virtual Machines in other regions, as a possible workaround. Engineers have identified a possible fix for the underlying cause, and are exploring implementation options. The next update will be provided as events warrant.",
            "stage": "Active",
            "communicationId": "636439673646212912",
            "version": "0.1.1"
          },
          "status": "Active",
          "subscriptionId": "45529734-0ed9-4895-a0df-44b59a5a07f9",
          "submissionTimestamp": "2017-10-18T23:49:28.7864349+00:00"
        }"#;

        let sh: ServiceHealth = serde_json::from_str(buf).unwrap();
        println!("{:#?}", sh);
        assert_eq!(sh.event_source, "ServiceHealth");

        // Just check one other member to make sure it didn't get defaulted.
        assert_eq!(
            sh.subscription_id,
            Uuid::parse_str("45529734-0ed9-4895-a0df-44b59a5a07f9").unwrap()
        );
    }

    #[test]
    fn test_de_service_health_partial() {
        let buf = r#"{
          "description": "Active: Virtual Machines - Australia East",
          "eventSource": "ServiceHealth"
        }"#;

        let sh: ServiceHealth = serde_json::from_str(buf).unwrap();
        println!("{:#?}", sh);
        assert_eq!(sh.event_source, "ServiceHealth");
    }

    #[test]
    #[should_panic(expected = "eventSource is")]
    fn test_de_service_health_partial_wrong_source() {
        let buf = r#"{
          "description": "Active: Virtual Machines - Australia East",
          "eventSource": "ThisIsNotServiceHealth"
        }"#;

        let _sh: ServiceHealth = serde_json::from_str(buf).unwrap();
    }
}
