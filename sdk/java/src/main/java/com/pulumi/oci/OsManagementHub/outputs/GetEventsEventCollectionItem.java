// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.OsManagementHub.outputs.GetEventsEventCollectionItemData;
import com.pulumi.oci.OsManagementHub.outputs.GetEventsEventCollectionItemSystemDetail;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetEventsEventCollectionItem {
    /**
     * @return The OCID of the compartment that contains the resources to list. This filter returns only resources contained within the specified compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return Provides additional information for a management station event.
     * 
     */
    private List<GetEventsEventCollectionItemData> datas;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return Details of an event.
     * 
     */
    private String eventDetails;
    private String eventId;
    /**
     * @return A filter to return only events whose summary matches the given value.
     * 
     */
    private String eventSummary;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the event.
     * 
     */
    private String id;
    /**
     * @return Indicates whether to list only resources managed by the Autonomous Linux service.
     * 
     */
    private Boolean isManagedByAutonomousLinux;
    /**
     * @return Describes the current state of the event in more detail. For example, the  message can provide actionable information for a resource in the &#39;FAILED&#39; state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource. This filter returns resources associated with the specified resource.
     * 
     */
    private String resourceId;
    /**
     * @return A filter to return only events that match the state provided. The state value is case-insensitive.
     * 
     */
    private String state;
    /**
     * @return Provides information about the system architecture and operating system.
     * 
     */
    private List<GetEventsEventCollectionItemSystemDetail> systemDetails;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,String> systemTags;
    /**
     * @return The date and time the Event was created, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time that the event occurred.
     * 
     */
    private String timeOccurred;
    /**
     * @return The date and time that the event was updated (in [RFC 3339](https://tools.ietf.org/html/rfc3339) format). Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeUpdated;
    /**
     * @return A filter to return only resources whose type matches the given value.
     * 
     */
    private String type;

    private GetEventsEventCollectionItem() {}
    /**
     * @return The OCID of the compartment that contains the resources to list. This filter returns only resources contained within the specified compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Provides additional information for a management station event.
     * 
     */
    public List<GetEventsEventCollectionItemData> datas() {
        return this.datas;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Details of an event.
     * 
     */
    public String eventDetails() {
        return this.eventDetails;
    }
    public String eventId() {
        return this.eventId;
    }
    /**
     * @return A filter to return only events whose summary matches the given value.
     * 
     */
    public String eventSummary() {
        return this.eventSummary;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the event.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Indicates whether to list only resources managed by the Autonomous Linux service.
     * 
     */
    public Boolean isManagedByAutonomousLinux() {
        return this.isManagedByAutonomousLinux;
    }
    /**
     * @return Describes the current state of the event in more detail. For example, the  message can provide actionable information for a resource in the &#39;FAILED&#39; state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource. This filter returns resources associated with the specified resource.
     * 
     */
    public String resourceId() {
        return this.resourceId;
    }
    /**
     * @return A filter to return only events that match the state provided. The state value is case-insensitive.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Provides information about the system architecture and operating system.
     * 
     */
    public List<GetEventsEventCollectionItemSystemDetail> systemDetails() {
        return this.systemDetails;
    }
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The date and time the Event was created, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time that the event occurred.
     * 
     */
    public String timeOccurred() {
        return this.timeOccurred;
    }
    /**
     * @return The date and time that the event was updated (in [RFC 3339](https://tools.ietf.org/html/rfc3339) format). Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return A filter to return only resources whose type matches the given value.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetEventsEventCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private List<GetEventsEventCollectionItemData> datas;
        private Map<String,String> definedTags;
        private String eventDetails;
        private String eventId;
        private String eventSummary;
        private Map<String,String> freeformTags;
        private String id;
        private Boolean isManagedByAutonomousLinux;
        private String lifecycleDetails;
        private String resourceId;
        private String state;
        private List<GetEventsEventCollectionItemSystemDetail> systemDetails;
        private Map<String,String> systemTags;
        private String timeCreated;
        private String timeOccurred;
        private String timeUpdated;
        private String type;
        public Builder() {}
        public Builder(GetEventsEventCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.datas = defaults.datas;
    	      this.definedTags = defaults.definedTags;
    	      this.eventDetails = defaults.eventDetails;
    	      this.eventId = defaults.eventId;
    	      this.eventSummary = defaults.eventSummary;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isManagedByAutonomousLinux = defaults.isManagedByAutonomousLinux;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.resourceId = defaults.resourceId;
    	      this.state = defaults.state;
    	      this.systemDetails = defaults.systemDetails;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeOccurred = defaults.timeOccurred;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetEventsEventCollectionItem", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder datas(List<GetEventsEventCollectionItemData> datas) {
            if (datas == null) {
              throw new MissingRequiredPropertyException("GetEventsEventCollectionItem", "datas");
            }
            this.datas = datas;
            return this;
        }
        public Builder datas(GetEventsEventCollectionItemData... datas) {
            return datas(List.of(datas));
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetEventsEventCollectionItem", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder eventDetails(String eventDetails) {
            if (eventDetails == null) {
              throw new MissingRequiredPropertyException("GetEventsEventCollectionItem", "eventDetails");
            }
            this.eventDetails = eventDetails;
            return this;
        }
        @CustomType.Setter
        public Builder eventId(String eventId) {
            if (eventId == null) {
              throw new MissingRequiredPropertyException("GetEventsEventCollectionItem", "eventId");
            }
            this.eventId = eventId;
            return this;
        }
        @CustomType.Setter
        public Builder eventSummary(String eventSummary) {
            if (eventSummary == null) {
              throw new MissingRequiredPropertyException("GetEventsEventCollectionItem", "eventSummary");
            }
            this.eventSummary = eventSummary;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetEventsEventCollectionItem", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetEventsEventCollectionItem", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isManagedByAutonomousLinux(Boolean isManagedByAutonomousLinux) {
            if (isManagedByAutonomousLinux == null) {
              throw new MissingRequiredPropertyException("GetEventsEventCollectionItem", "isManagedByAutonomousLinux");
            }
            this.isManagedByAutonomousLinux = isManagedByAutonomousLinux;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetEventsEventCollectionItem", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder resourceId(String resourceId) {
            if (resourceId == null) {
              throw new MissingRequiredPropertyException("GetEventsEventCollectionItem", "resourceId");
            }
            this.resourceId = resourceId;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetEventsEventCollectionItem", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemDetails(List<GetEventsEventCollectionItemSystemDetail> systemDetails) {
            if (systemDetails == null) {
              throw new MissingRequiredPropertyException("GetEventsEventCollectionItem", "systemDetails");
            }
            this.systemDetails = systemDetails;
            return this;
        }
        public Builder systemDetails(GetEventsEventCollectionItemSystemDetail... systemDetails) {
            return systemDetails(List.of(systemDetails));
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,String> systemTags) {
            if (systemTags == null) {
              throw new MissingRequiredPropertyException("GetEventsEventCollectionItem", "systemTags");
            }
            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetEventsEventCollectionItem", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeOccurred(String timeOccurred) {
            if (timeOccurred == null) {
              throw new MissingRequiredPropertyException("GetEventsEventCollectionItem", "timeOccurred");
            }
            this.timeOccurred = timeOccurred;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetEventsEventCollectionItem", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetEventsEventCollectionItem", "type");
            }
            this.type = type;
            return this;
        }
        public GetEventsEventCollectionItem build() {
            final var _resultValue = new GetEventsEventCollectionItem();
            _resultValue.compartmentId = compartmentId;
            _resultValue.datas = datas;
            _resultValue.definedTags = definedTags;
            _resultValue.eventDetails = eventDetails;
            _resultValue.eventId = eventId;
            _resultValue.eventSummary = eventSummary;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.isManagedByAutonomousLinux = isManagedByAutonomousLinux;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.resourceId = resourceId;
            _resultValue.state = state;
            _resultValue.systemDetails = systemDetails;
            _resultValue.systemTags = systemTags;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeOccurred = timeOccurred;
            _resultValue.timeUpdated = timeUpdated;
            _resultValue.type = type;
            return _resultValue;
        }
    }
}
