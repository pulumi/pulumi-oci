// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApmSynthetics.outputs.GetDedicatedVantagePointDvpStackDetail;
import com.pulumi.oci.ApmSynthetics.outputs.GetDedicatedVantagePointMonitorStatusCountMap;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetDedicatedVantagePointResult {
    private String apmDomainId;
    private String dedicatedVantagePointId;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return Unique dedicated vantage point name that cannot be edited. The name should not contain any confidential information.
     * 
     */
    private String displayName;
    /**
     * @return Details of a Dedicated Vantage Point (DVP) stack in Resource Manager.
     * 
     */
    private List<GetDedicatedVantagePointDvpStackDetail> dvpStackDetails;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the dedicated vantage point.
     * 
     */
    private String id;
    /**
     * @return Details of the monitor count per state. Example: `{ &#34;total&#34; : 5, &#34;enabled&#34; : 3 , &#34;disabled&#34; : 2, &#34;invalid&#34; : 0 }`
     * 
     */
    private List<GetDedicatedVantagePointMonitorStatusCountMap> monitorStatusCountMaps;
    /**
     * @return Unique permanent name of the dedicated vantage point. This is the same as the displayName.
     * 
     */
    private String name;
    /**
     * @return Name of the region.
     * 
     */
    private String region;
    /**
     * @return Status of the dedicated vantage point.
     * 
     */
    private String status;
    /**
     * @return The time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
     * 
     */
    private String timeCreated;
    /**
     * @return The time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-13T22:47:12.613Z`
     * 
     */
    private String timeUpdated;

    private GetDedicatedVantagePointResult() {}
    public String apmDomainId() {
        return this.apmDomainId;
    }
    public String dedicatedVantagePointId() {
        return this.dedicatedVantagePointId;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return Unique dedicated vantage point name that cannot be edited. The name should not contain any confidential information.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Details of a Dedicated Vantage Point (DVP) stack in Resource Manager.
     * 
     */
    public List<GetDedicatedVantagePointDvpStackDetail> dvpStackDetails() {
        return this.dvpStackDetails;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the dedicated vantage point.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Details of the monitor count per state. Example: `{ &#34;total&#34; : 5, &#34;enabled&#34; : 3 , &#34;disabled&#34; : 2, &#34;invalid&#34; : 0 }`
     * 
     */
    public List<GetDedicatedVantagePointMonitorStatusCountMap> monitorStatusCountMaps() {
        return this.monitorStatusCountMaps;
    }
    /**
     * @return Unique permanent name of the dedicated vantage point. This is the same as the displayName.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Name of the region.
     * 
     */
    public String region() {
        return this.region;
    }
    /**
     * @return Status of the dedicated vantage point.
     * 
     */
    public String status() {
        return this.status;
    }
    /**
     * @return The time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-13T22:47:12.613Z`
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDedicatedVantagePointResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String apmDomainId;
        private String dedicatedVantagePointId;
        private Map<String,Object> definedTags;
        private String displayName;
        private List<GetDedicatedVantagePointDvpStackDetail> dvpStackDetails;
        private Map<String,Object> freeformTags;
        private String id;
        private List<GetDedicatedVantagePointMonitorStatusCountMap> monitorStatusCountMaps;
        private String name;
        private String region;
        private String status;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetDedicatedVantagePointResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.apmDomainId = defaults.apmDomainId;
    	      this.dedicatedVantagePointId = defaults.dedicatedVantagePointId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.dvpStackDetails = defaults.dvpStackDetails;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.monitorStatusCountMaps = defaults.monitorStatusCountMaps;
    	      this.name = defaults.name;
    	      this.region = defaults.region;
    	      this.status = defaults.status;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder apmDomainId(String apmDomainId) {
            this.apmDomainId = Objects.requireNonNull(apmDomainId);
            return this;
        }
        @CustomType.Setter
        public Builder dedicatedVantagePointId(String dedicatedVantagePointId) {
            this.dedicatedVantagePointId = Objects.requireNonNull(dedicatedVantagePointId);
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder dvpStackDetails(List<GetDedicatedVantagePointDvpStackDetail> dvpStackDetails) {
            this.dvpStackDetails = Objects.requireNonNull(dvpStackDetails);
            return this;
        }
        public Builder dvpStackDetails(GetDedicatedVantagePointDvpStackDetail... dvpStackDetails) {
            return dvpStackDetails(List.of(dvpStackDetails));
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder monitorStatusCountMaps(List<GetDedicatedVantagePointMonitorStatusCountMap> monitorStatusCountMaps) {
            this.monitorStatusCountMaps = Objects.requireNonNull(monitorStatusCountMaps);
            return this;
        }
        public Builder monitorStatusCountMaps(GetDedicatedVantagePointMonitorStatusCountMap... monitorStatusCountMaps) {
            return monitorStatusCountMaps(List.of(monitorStatusCountMaps));
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        @CustomType.Setter
        public Builder region(String region) {
            this.region = Objects.requireNonNull(region);
            return this;
        }
        @CustomType.Setter
        public Builder status(String status) {
            this.status = Objects.requireNonNull(status);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }
        public GetDedicatedVantagePointResult build() {
            final var o = new GetDedicatedVantagePointResult();
            o.apmDomainId = apmDomainId;
            o.dedicatedVantagePointId = dedicatedVantagePointId;
            o.definedTags = definedTags;
            o.displayName = displayName;
            o.dvpStackDetails = dvpStackDetails;
            o.freeformTags = freeformTags;
            o.id = id;
            o.monitorStatusCountMaps = monitorStatusCountMaps;
            o.name = name;
            o.region = region;
            o.status = status;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            return o;
        }
    }
}