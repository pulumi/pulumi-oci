// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Double;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetDedicatedVmHostsDedicatedVmHost {
    /**
     * @return The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    private final String availabilityDomain;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private final String compartmentId;
    /**
     * @return The dedicated virtual machine host shape. The shape determines the number of CPUs and other resources available for VMs.
     * 
     */
    private final String dedicatedVmHostShape;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private final Map<String,Object> definedTags;
    /**
     * @return A filter to return only resources that match the given display name exactly.
     * 
     */
    private final String displayName;
    /**
     * @return The fault domain for the dedicated virtual machine host&#39;s assigned instances. For more information, see [Fault Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm#fault).
     * 
     */
    private final String faultDomain;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private final Map<String,Object> freeformTags;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the dedicated VM host.
     * 
     */
    private final String id;
    /**
     * @return The current available memory of the dedicated VM host, in GBs.
     * 
     */
    private final Double remainingMemoryInGbs;
    /**
     * @return The current available OCPUs of the dedicated VM host.
     * 
     */
    private final Double remainingOcpus;
    /**
     * @return A filter to only return resources that match the given lifecycle state.
     * 
     */
    private final String state;
    /**
     * @return The date and time the dedicated VM host was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private final String timeCreated;
    /**
     * @return The current total memory of the dedicated VM host, in GBs.
     * 
     */
    private final Double totalMemoryInGbs;
    /**
     * @return The current total OCPUs of the dedicated VM host.
     * 
     */
    private final Double totalOcpus;

    @CustomType.Constructor
    private GetDedicatedVmHostsDedicatedVmHost(
        @CustomType.Parameter("availabilityDomain") String availabilityDomain,
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("dedicatedVmHostShape") String dedicatedVmHostShape,
        @CustomType.Parameter("definedTags") Map<String,Object> definedTags,
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("faultDomain") String faultDomain,
        @CustomType.Parameter("freeformTags") Map<String,Object> freeformTags,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("remainingMemoryInGbs") Double remainingMemoryInGbs,
        @CustomType.Parameter("remainingOcpus") Double remainingOcpus,
        @CustomType.Parameter("state") String state,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("totalMemoryInGbs") Double totalMemoryInGbs,
        @CustomType.Parameter("totalOcpus") Double totalOcpus) {
        this.availabilityDomain = availabilityDomain;
        this.compartmentId = compartmentId;
        this.dedicatedVmHostShape = dedicatedVmHostShape;
        this.definedTags = definedTags;
        this.displayName = displayName;
        this.faultDomain = faultDomain;
        this.freeformTags = freeformTags;
        this.id = id;
        this.remainingMemoryInGbs = remainingMemoryInGbs;
        this.remainingOcpus = remainingOcpus;
        this.state = state;
        this.timeCreated = timeCreated;
        this.totalMemoryInGbs = totalMemoryInGbs;
        this.totalOcpus = totalOcpus;
    }

    /**
     * @return The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The dedicated virtual machine host shape. The shape determines the number of CPUs and other resources available for VMs.
     * 
     */
    public String dedicatedVmHostShape() {
        return this.dedicatedVmHostShape;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A filter to return only resources that match the given display name exactly.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return The fault domain for the dedicated virtual machine host&#39;s assigned instances. For more information, see [Fault Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm#fault).
     * 
     */
    public String faultDomain() {
        return this.faultDomain;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the dedicated VM host.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The current available memory of the dedicated VM host, in GBs.
     * 
     */
    public Double remainingMemoryInGbs() {
        return this.remainingMemoryInGbs;
    }
    /**
     * @return The current available OCPUs of the dedicated VM host.
     * 
     */
    public Double remainingOcpus() {
        return this.remainingOcpus;
    }
    /**
     * @return A filter to only return resources that match the given lifecycle state.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the dedicated VM host was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The current total memory of the dedicated VM host, in GBs.
     * 
     */
    public Double totalMemoryInGbs() {
        return this.totalMemoryInGbs;
    }
    /**
     * @return The current total OCPUs of the dedicated VM host.
     * 
     */
    public Double totalOcpus() {
        return this.totalOcpus;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDedicatedVmHostsDedicatedVmHost defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String availabilityDomain;
        private String compartmentId;
        private String dedicatedVmHostShape;
        private Map<String,Object> definedTags;
        private String displayName;
        private String faultDomain;
        private Map<String,Object> freeformTags;
        private String id;
        private Double remainingMemoryInGbs;
        private Double remainingOcpus;
        private String state;
        private String timeCreated;
        private Double totalMemoryInGbs;
        private Double totalOcpus;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDedicatedVmHostsDedicatedVmHost defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.compartmentId = defaults.compartmentId;
    	      this.dedicatedVmHostShape = defaults.dedicatedVmHostShape;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.faultDomain = defaults.faultDomain;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.remainingMemoryInGbs = defaults.remainingMemoryInGbs;
    	      this.remainingOcpus = defaults.remainingOcpus;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.totalMemoryInGbs = defaults.totalMemoryInGbs;
    	      this.totalOcpus = defaults.totalOcpus;
        }

        public Builder availabilityDomain(String availabilityDomain) {
            this.availabilityDomain = Objects.requireNonNull(availabilityDomain);
            return this;
        }
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder dedicatedVmHostShape(String dedicatedVmHostShape) {
            this.dedicatedVmHostShape = Objects.requireNonNull(dedicatedVmHostShape);
            return this;
        }
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        public Builder faultDomain(String faultDomain) {
            this.faultDomain = Objects.requireNonNull(faultDomain);
            return this;
        }
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder remainingMemoryInGbs(Double remainingMemoryInGbs) {
            this.remainingMemoryInGbs = Objects.requireNonNull(remainingMemoryInGbs);
            return this;
        }
        public Builder remainingOcpus(Double remainingOcpus) {
            this.remainingOcpus = Objects.requireNonNull(remainingOcpus);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public Builder totalMemoryInGbs(Double totalMemoryInGbs) {
            this.totalMemoryInGbs = Objects.requireNonNull(totalMemoryInGbs);
            return this;
        }
        public Builder totalOcpus(Double totalOcpus) {
            this.totalOcpus = Objects.requireNonNull(totalOcpus);
            return this;
        }        public GetDedicatedVmHostsDedicatedVmHost build() {
            return new GetDedicatedVmHostsDedicatedVmHost(availabilityDomain, compartmentId, dedicatedVmHostShape, definedTags, displayName, faultDomain, freeformTags, id, remainingMemoryInGbs, remainingOcpus, state, timeCreated, totalMemoryInGbs, totalOcpus);
        }
    }
}
