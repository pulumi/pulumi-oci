// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Audit.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Audit.outputs.GetEventsAuditEventData;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetEventsAuditEvent {
    /**
     * @return The version of the CloudEvents specification. The structure of the envelope follows the  [CloudEvents](https://github.com/cloudevents/spec) industry standard format hosted by the [Cloud Native Computing Foundation ( CNCF)](https://www.cncf.io/).
     * 
     */
    private String cloudEventsVersion;
    /**
     * @return The content type of the data contained in `data`.  Example: `application/json`
     * 
     */
    private String contentType;
    /**
     * @return The payload of the event. Information within `data` comes from the resource emitting the event.
     * 
     */
    private List<GetEventsAuditEventData> datas;
    /**
     * @return The GUID of the event.
     * 
     */
    private String eventId;
    /**
     * @return The time the event occurred, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2019-09-18T00:10:59.252Z`
     * 
     */
    private String eventTime;
    /**
     * @return The type of event that happened.
     * 
     */
    private String eventType;
    /**
     * @return The version of the event type. This version applies to the payload of the event, not the envelope. Use `cloudEventsVersion` to determine the version of the envelope.  Example: `2.0`
     * 
     */
    private String eventTypeVersion;
    /**
     * @return The source of the event.  Example: `ComputeApi`
     * 
     */
    private String source;

    private GetEventsAuditEvent() {}
    /**
     * @return The version of the CloudEvents specification. The structure of the envelope follows the  [CloudEvents](https://github.com/cloudevents/spec) industry standard format hosted by the [Cloud Native Computing Foundation ( CNCF)](https://www.cncf.io/).
     * 
     */
    public String cloudEventsVersion() {
        return this.cloudEventsVersion;
    }
    /**
     * @return The content type of the data contained in `data`.  Example: `application/json`
     * 
     */
    public String contentType() {
        return this.contentType;
    }
    /**
     * @return The payload of the event. Information within `data` comes from the resource emitting the event.
     * 
     */
    public List<GetEventsAuditEventData> datas() {
        return this.datas;
    }
    /**
     * @return The GUID of the event.
     * 
     */
    public String eventId() {
        return this.eventId;
    }
    /**
     * @return The time the event occurred, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2019-09-18T00:10:59.252Z`
     * 
     */
    public String eventTime() {
        return this.eventTime;
    }
    /**
     * @return The type of event that happened.
     * 
     */
    public String eventType() {
        return this.eventType;
    }
    /**
     * @return The version of the event type. This version applies to the payload of the event, not the envelope. Use `cloudEventsVersion` to determine the version of the envelope.  Example: `2.0`
     * 
     */
    public String eventTypeVersion() {
        return this.eventTypeVersion;
    }
    /**
     * @return The source of the event.  Example: `ComputeApi`
     * 
     */
    public String source() {
        return this.source;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetEventsAuditEvent defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String cloudEventsVersion;
        private String contentType;
        private List<GetEventsAuditEventData> datas;
        private String eventId;
        private String eventTime;
        private String eventType;
        private String eventTypeVersion;
        private String source;
        public Builder() {}
        public Builder(GetEventsAuditEvent defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.cloudEventsVersion = defaults.cloudEventsVersion;
    	      this.contentType = defaults.contentType;
    	      this.datas = defaults.datas;
    	      this.eventId = defaults.eventId;
    	      this.eventTime = defaults.eventTime;
    	      this.eventType = defaults.eventType;
    	      this.eventTypeVersion = defaults.eventTypeVersion;
    	      this.source = defaults.source;
        }

        @CustomType.Setter
        public Builder cloudEventsVersion(String cloudEventsVersion) {
            if (cloudEventsVersion == null) {
              throw new MissingRequiredPropertyException("GetEventsAuditEvent", "cloudEventsVersion");
            }
            this.cloudEventsVersion = cloudEventsVersion;
            return this;
        }
        @CustomType.Setter
        public Builder contentType(String contentType) {
            if (contentType == null) {
              throw new MissingRequiredPropertyException("GetEventsAuditEvent", "contentType");
            }
            this.contentType = contentType;
            return this;
        }
        @CustomType.Setter
        public Builder datas(List<GetEventsAuditEventData> datas) {
            if (datas == null) {
              throw new MissingRequiredPropertyException("GetEventsAuditEvent", "datas");
            }
            this.datas = datas;
            return this;
        }
        public Builder datas(GetEventsAuditEventData... datas) {
            return datas(List.of(datas));
        }
        @CustomType.Setter
        public Builder eventId(String eventId) {
            if (eventId == null) {
              throw new MissingRequiredPropertyException("GetEventsAuditEvent", "eventId");
            }
            this.eventId = eventId;
            return this;
        }
        @CustomType.Setter
        public Builder eventTime(String eventTime) {
            if (eventTime == null) {
              throw new MissingRequiredPropertyException("GetEventsAuditEvent", "eventTime");
            }
            this.eventTime = eventTime;
            return this;
        }
        @CustomType.Setter
        public Builder eventType(String eventType) {
            if (eventType == null) {
              throw new MissingRequiredPropertyException("GetEventsAuditEvent", "eventType");
            }
            this.eventType = eventType;
            return this;
        }
        @CustomType.Setter
        public Builder eventTypeVersion(String eventTypeVersion) {
            if (eventTypeVersion == null) {
              throw new MissingRequiredPropertyException("GetEventsAuditEvent", "eventTypeVersion");
            }
            this.eventTypeVersion = eventTypeVersion;
            return this;
        }
        @CustomType.Setter
        public Builder source(String source) {
            if (source == null) {
              throw new MissingRequiredPropertyException("GetEventsAuditEvent", "source");
            }
            this.source = source;
            return this;
        }
        public GetEventsAuditEvent build() {
            final var _resultValue = new GetEventsAuditEvent();
            _resultValue.cloudEventsVersion = cloudEventsVersion;
            _resultValue.contentType = contentType;
            _resultValue.datas = datas;
            _resultValue.eventId = eventId;
            _resultValue.eventTime = eventTime;
            _resultValue.eventType = eventType;
            _resultValue.eventTypeVersion = eventTypeVersion;
            _resultValue.source = source;
            return _resultValue;
        }
    }
}
