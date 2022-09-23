use chrono::{DateTime, Utc};
use serde::{self, Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::str::FromStr;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
#[allow(unused)]
pub struct ActivityLog {
    pub schema_id: String,
    pub data: AlertData,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
#[allow(unused)]
pub struct AlertData {
    pub status: String,
    #[serde(default)]
    pub properties: HashMap<String, String>,
    pub context: AlertContext,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
#[allow(unused)]
pub struct AlertContext {
    pub activity_log: InnerActivityLog,
}

// ServiceHealth is only larger than the others because the others aren't implemented yet.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(untagged)]
pub enum InnerActivityLog {
    #[default]
    Dummy,
    Security(Security),
    Recommendation(Recommendation),
    ServiceHealth(ServiceHealth),
    ResourceHealth(ResourceHealth),
    Administrative(Administrative),
}

// common fields would use flatten

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default, rename_all = "camelCase")]
#[allow(unused)]
pub struct ServiceHealth {
    pub channels: String, // Enum?
    #[serde(deserialize_with = "deserialize_uuid_base64")]
    pub correlation_id: Uuid,
    pub description: String,
    #[serde(deserialize_with = "deserialize_event_source_service_health")]
    pub event_source: String, // must be "ServiceHealth"
    pub event_timestamp: DateTime<Utc>,
    #[serde(deserialize_with = "deserialize_uuid_base64")]
    pub event_data_id: Uuid,
    pub level: String, // Enum?
    pub operation_name: String,
    #[serde(deserialize_with = "deserialize_uuid_base64")]
    pub operation_id: Uuid,
    pub status: String, // Enum?
    #[serde(deserialize_with = "deserialize_uuid_base64")]
    pub subscription_id: Uuid,
    pub properties: ServiceHealthProperties,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default, rename_all = "camelCase")]
#[allow(unused)]
pub struct ServiceHealthProperties {
    pub title: String,
    pub service: String,
    pub region: String,
    pub communication: String,
    pub incident_type: String, // Enum?
    pub tracking_id: String,
    pub impact_start_time: DateTime<Utc>,
    pub impacted_services: String, // JSON
    pub default_language_title: String,
    pub default_language_content: String,
    pub stage: String, // Enum?
    pub communication_id: String,
    pub version: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default, rename_all = "camelCase")]
#[allow(unused)]
pub struct Recommendation {
    #[serde(deserialize_with = "deserialize_event_source_recommendation")]
    event_source: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default, rename_all = "camelCase")]
#[allow(unused)]
pub struct Security {
    #[serde(deserialize_with = "deserialize_event_source_security_log")]
    event_source: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default, rename_all = "camelCase")]
#[allow(unused)]
pub struct ResourceHealth {
    #[serde(deserialize_with = "deserialize_event_source_resource_health")]
    event_source: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default, rename_all = "camelCase")]
#[allow(unused)]
pub struct Administrative {
    #[serde(deserialize_with = "deserialize_event_source_administrative")]
    event_source: String,
}

/// Try to deserialize a UUID first, and if that fails, try base64-decoding and then converting to
/// a UUID.  This assumes that the input is deserializable as a String.  This is useful when
/// pulling documents out of MongoDB, which will have serialized the UUID byte blob as base64.
fn deserialize_uuid_base64<'de, D>(deserializer: D) -> Result<Uuid, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    // If we can't decode from a string, then something's wrong.
    let s = String::deserialize(deserializer)?;

    // If Uuid can make sense of that, great.
    if let Ok(uu) = Uuid::from_str(s.as_ref()) {
        return Ok(uu);
    }

    // Otherwise, try to base64-decode.
    let uuid_bytes = base64::decode(s).map_err(Error::custom)?;

    // Convert the resulting Vec<u8> to &[u8] and see if that's a UUID.
    Uuid::from_slice(uuid_bytes.as_slice()).map_err(Error::custom)
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
    deserialize_event_source_generic(deserializer, "Security")
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

    // For now, at least, Security isn't fully implemented, but we should still get back a Security
    // object.
    #[test]
    fn test_de_activity_log_security_log() {
        let buf = r#"
            {
              "schemaId": "Microsoft.Insights/activityLogs",
              "data": {
                "status": "Activated",
                "properties": {},
                "context": {
                  "activityLog": {
                    "description": "Active: Virtual Machines - Australia East",
                    "eventSource": "Security"
                  }
                }
              }
            }
        "#;

        // Can we deserialize at all?
        let al: ActivityLog = serde_json::from_str(buf).unwrap();
        println!("{:#?}", al);

        // Did it end up as a Security log?
        if let InnerActivityLog::Security(s) = al.data.context.activity_log {
            assert_eq!(s.event_source, "Security");
        } else {
            panic!("Incorrect activity log type (not Security)");
        }
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

    #[test]
    fn test_base64_uuid() {
        let buf = r#"{
            "eventSource": "ServiceHealth",
            "correlationId": "u6yUT93AS0yqhcx9xdXBpg=="
        }"#;

        let sh: ServiceHealth = serde_json::from_str(buf).unwrap();
        assert_eq!(sh.event_source, "ServiceHealth");
        assert_eq!(
            sh.correlation_id,
            Uuid::from_str("bbac944f-ddc0-4b4c-aa85-cc7dc5d5c1a6").unwrap()
        );
    }
}
