// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataFlow.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataFlow.outputs.GetPoolConfiguration;
import com.pulumi.oci.DataFlow.outputs.GetPoolPoolMetric;
import com.pulumi.oci.DataFlow.outputs.GetPoolSchedule;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetPoolResult {
    /**
     * @return The OCID of a compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return List of PoolConfig items.
     * 
     */
    private List<GetPoolConfiguration> configurations;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return A user-friendly description. Avoid entering confidential information.
     * 
     */
    private String description;
    /**
     * @return A user-friendly name. It does not have to be unique. Avoid entering confidential information.
     * 
     */
    private String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The OCID of a pool. Unique Id to indentify a dataflow pool resource.
     * 
     */
    private String id;
    /**
     * @return Optional timeout value in minutes used to auto stop Pools. A Pool will be auto stopped after inactivity for this amount of time period. If value not set, pool will not be auto stopped auto.
     * 
     */
    private Integer idleTimeoutInMinutes;
    /**
     * @return The detailed messages about the lifecycle state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return The OCID of the user who created the resource.
     * 
     */
    private String ownerPrincipalId;
    /**
     * @return The username of the user who created the resource.  If the username of the owner does not exist, `null` will be returned and the caller should refer to the ownerPrincipalId value instead.
     * 
     */
    private String ownerUserName;
    private String poolId;
    /**
     * @return A collection of metrics related to a particular pool.
     * 
     */
    private List<GetPoolPoolMetric> poolMetrics;
    /**
     * @return A list of schedules for pool to auto start and stop.
     * 
     */
    private List<GetPoolSchedule> schedules;
    /**
     * @return The current state of this pool.
     * 
     */
    private String state;
    /**
     * @return The date and time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     * 
     */
    private String timeUpdated;

    private GetPoolResult() {}
    /**
     * @return The OCID of a compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return List of PoolConfig items.
     * 
     */
    public List<GetPoolConfiguration> configurations() {
        return this.configurations;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A user-friendly description. Avoid entering confidential information.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return A user-friendly name. It does not have to be unique. Avoid entering confidential information.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The OCID of a pool. Unique Id to indentify a dataflow pool resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Optional timeout value in minutes used to auto stop Pools. A Pool will be auto stopped after inactivity for this amount of time period. If value not set, pool will not be auto stopped auto.
     * 
     */
    public Integer idleTimeoutInMinutes() {
        return this.idleTimeoutInMinutes;
    }
    /**
     * @return The detailed messages about the lifecycle state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return The OCID of the user who created the resource.
     * 
     */
    public String ownerPrincipalId() {
        return this.ownerPrincipalId;
    }
    /**
     * @return The username of the user who created the resource.  If the username of the owner does not exist, `null` will be returned and the caller should refer to the ownerPrincipalId value instead.
     * 
     */
    public String ownerUserName() {
        return this.ownerUserName;
    }
    public String poolId() {
        return this.poolId;
    }
    /**
     * @return A collection of metrics related to a particular pool.
     * 
     */
    public List<GetPoolPoolMetric> poolMetrics() {
        return this.poolMetrics;
    }
    /**
     * @return A list of schedules for pool to auto start and stop.
     * 
     */
    public List<GetPoolSchedule> schedules() {
        return this.schedules;
    }
    /**
     * @return The current state of this pool.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPoolResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private List<GetPoolConfiguration> configurations;
        private Map<String,Object> definedTags;
        private String description;
        private String displayName;
        private Map<String,Object> freeformTags;
        private String id;
        private Integer idleTimeoutInMinutes;
        private String lifecycleDetails;
        private String ownerPrincipalId;
        private String ownerUserName;
        private String poolId;
        private List<GetPoolPoolMetric> poolMetrics;
        private List<GetPoolSchedule> schedules;
        private String state;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetPoolResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.configurations = defaults.configurations;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.idleTimeoutInMinutes = defaults.idleTimeoutInMinutes;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.ownerPrincipalId = defaults.ownerPrincipalId;
    	      this.ownerUserName = defaults.ownerUserName;
    	      this.poolId = defaults.poolId;
    	      this.poolMetrics = defaults.poolMetrics;
    	      this.schedules = defaults.schedules;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder configurations(List<GetPoolConfiguration> configurations) {
            this.configurations = Objects.requireNonNull(configurations);
            return this;
        }
        public Builder configurations(GetPoolConfiguration... configurations) {
            return configurations(List.of(configurations));
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
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
        public Builder idleTimeoutInMinutes(Integer idleTimeoutInMinutes) {
            this.idleTimeoutInMinutes = Objects.requireNonNull(idleTimeoutInMinutes);
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        @CustomType.Setter
        public Builder ownerPrincipalId(String ownerPrincipalId) {
            this.ownerPrincipalId = Objects.requireNonNull(ownerPrincipalId);
            return this;
        }
        @CustomType.Setter
        public Builder ownerUserName(String ownerUserName) {
            this.ownerUserName = Objects.requireNonNull(ownerUserName);
            return this;
        }
        @CustomType.Setter
        public Builder poolId(String poolId) {
            this.poolId = Objects.requireNonNull(poolId);
            return this;
        }
        @CustomType.Setter
        public Builder poolMetrics(List<GetPoolPoolMetric> poolMetrics) {
            this.poolMetrics = Objects.requireNonNull(poolMetrics);
            return this;
        }
        public Builder poolMetrics(GetPoolPoolMetric... poolMetrics) {
            return poolMetrics(List.of(poolMetrics));
        }
        @CustomType.Setter
        public Builder schedules(List<GetPoolSchedule> schedules) {
            this.schedules = Objects.requireNonNull(schedules);
            return this;
        }
        public Builder schedules(GetPoolSchedule... schedules) {
            return schedules(List.of(schedules));
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
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
        public GetPoolResult build() {
            final var o = new GetPoolResult();
            o.compartmentId = compartmentId;
            o.configurations = configurations;
            o.definedTags = definedTags;
            o.description = description;
            o.displayName = displayName;
            o.freeformTags = freeformTags;
            o.id = id;
            o.idleTimeoutInMinutes = idleTimeoutInMinutes;
            o.lifecycleDetails = lifecycleDetails;
            o.ownerPrincipalId = ownerPrincipalId;
            o.ownerUserName = ownerUserName;
            o.poolId = poolId;
            o.poolMetrics = poolMetrics;
            o.schedules = schedules;
            o.state = state;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            return o;
        }
    }
}