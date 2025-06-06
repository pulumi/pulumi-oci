// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataFlow;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataFlow.inputs.PoolConfigurationArgs;
import com.pulumi.oci.DataFlow.inputs.PoolScheduleArgs;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class PoolArgs extends com.pulumi.resources.ResourceArgs {

    public static final PoolArgs Empty = new PoolArgs();

    /**
     * (Updatable) The OCID of a compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of a compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) List of PoolConfig items.
     * 
     */
    @Import(name="configurations", required=true)
    private Output<List<PoolConfigurationArgs>> configurations;

    /**
     * @return (Updatable) List of PoolConfig items.
     * 
     */
    public Output<List<PoolConfigurationArgs>> configurations() {
        return this.configurations;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) A user-friendly description. Avoid entering confidential information.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) A user-friendly description. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) A user-friendly name. It does not have to be unique. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. It does not have to be unique. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) Optional timeout value in minutes used to auto stop Pools. A Pool will be auto stopped after inactivity for this amount of time period. If value not set, pool will not be auto stopped auto.
     * 
     */
    @Import(name="idleTimeoutInMinutes")
    private @Nullable Output<Integer> idleTimeoutInMinutes;

    /**
     * @return (Updatable) Optional timeout value in minutes used to auto stop Pools. A Pool will be auto stopped after inactivity for this amount of time period. If value not set, pool will not be auto stopped auto.
     * 
     */
    public Optional<Output<Integer>> idleTimeoutInMinutes() {
        return Optional.ofNullable(this.idleTimeoutInMinutes);
    }

    /**
     * (Updatable) A list of schedules for pool to auto start and stop.
     * 
     */
    @Import(name="schedules")
    private @Nullable Output<List<PoolScheduleArgs>> schedules;

    /**
     * @return (Updatable) A list of schedules for pool to auto start and stop.
     * 
     */
    public Optional<Output<List<PoolScheduleArgs>>> schedules() {
        return Optional.ofNullable(this.schedules);
    }

    /**
     * (Updatable) The target state for the Pool. Could be set to `ACTIVE` or `DELETED`.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return (Updatable) The target state for the Pool. Could be set to `ACTIVE` or `DELETED`.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private PoolArgs() {}

    private PoolArgs(PoolArgs $) {
        this.compartmentId = $.compartmentId;
        this.configurations = $.configurations;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.idleTimeoutInMinutes = $.idleTimeoutInMinutes;
        this.schedules = $.schedules;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(PoolArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private PoolArgs $;

        public Builder() {
            $ = new PoolArgs();
        }

        public Builder(PoolArgs defaults) {
            $ = new PoolArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The OCID of a compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The OCID of a compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param configurations (Updatable) List of PoolConfig items.
         * 
         * @return builder
         * 
         */
        public Builder configurations(Output<List<PoolConfigurationArgs>> configurations) {
            $.configurations = configurations;
            return this;
        }

        /**
         * @param configurations (Updatable) List of PoolConfig items.
         * 
         * @return builder
         * 
         */
        public Builder configurations(List<PoolConfigurationArgs> configurations) {
            return configurations(Output.of(configurations));
        }

        /**
         * @param configurations (Updatable) List of PoolConfig items.
         * 
         * @return builder
         * 
         */
        public Builder configurations(PoolConfigurationArgs... configurations) {
            return configurations(List.of(configurations));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description (Updatable) A user-friendly description. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) A user-friendly description. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) A user-friendly name. It does not have to be unique. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly name. It does not have to be unique. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param idleTimeoutInMinutes (Updatable) Optional timeout value in minutes used to auto stop Pools. A Pool will be auto stopped after inactivity for this amount of time period. If value not set, pool will not be auto stopped auto.
         * 
         * @return builder
         * 
         */
        public Builder idleTimeoutInMinutes(@Nullable Output<Integer> idleTimeoutInMinutes) {
            $.idleTimeoutInMinutes = idleTimeoutInMinutes;
            return this;
        }

        /**
         * @param idleTimeoutInMinutes (Updatable) Optional timeout value in minutes used to auto stop Pools. A Pool will be auto stopped after inactivity for this amount of time period. If value not set, pool will not be auto stopped auto.
         * 
         * @return builder
         * 
         */
        public Builder idleTimeoutInMinutes(Integer idleTimeoutInMinutes) {
            return idleTimeoutInMinutes(Output.of(idleTimeoutInMinutes));
        }

        /**
         * @param schedules (Updatable) A list of schedules for pool to auto start and stop.
         * 
         * @return builder
         * 
         */
        public Builder schedules(@Nullable Output<List<PoolScheduleArgs>> schedules) {
            $.schedules = schedules;
            return this;
        }

        /**
         * @param schedules (Updatable) A list of schedules for pool to auto start and stop.
         * 
         * @return builder
         * 
         */
        public Builder schedules(List<PoolScheduleArgs> schedules) {
            return schedules(Output.of(schedules));
        }

        /**
         * @param schedules (Updatable) A list of schedules for pool to auto start and stop.
         * 
         * @return builder
         * 
         */
        public Builder schedules(PoolScheduleArgs... schedules) {
            return schedules(List.of(schedules));
        }

        /**
         * @param state (Updatable) The target state for the Pool. Could be set to `ACTIVE` or `DELETED`.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state (Updatable) The target state for the Pool. Could be set to `ACTIVE` or `DELETED`.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public PoolArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("PoolArgs", "compartmentId");
            }
            if ($.configurations == null) {
                throw new MissingRequiredPropertyException("PoolArgs", "configurations");
            }
            if ($.displayName == null) {
                throw new MissingRequiredPropertyException("PoolArgs", "displayName");
            }
            return $;
        }
    }

}
