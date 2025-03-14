// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.inputs.ScheduledActionActionMemberArgs;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ScheduledActionArgs extends com.pulumi.resources.ResourceArgs {

    public static final ScheduledActionArgs Empty = new ScheduledActionArgs();

    /**
     * (Updatable) The list of action members in a scheduled action.
     * 
     */
    @Import(name="actionMembers")
    private @Nullable Output<List<ScheduledActionActionMemberArgs>> actionMembers;

    /**
     * @return (Updatable) The list of action members in a scheduled action.
     * 
     */
    public Optional<Output<List<ScheduledActionActionMemberArgs>>> actionMembers() {
        return Optional.ofNullable(this.actionMembers);
    }

    /**
     * (Updatable) Map&lt;ParamName, ParamValue&gt; where a key value pair describes the specific action parameter. Example: `{&#34;count&#34;: &#34;3&#34;}`
     * 
     */
    @Import(name="actionParams")
    private @Nullable Output<Map<String,String>> actionParams;

    /**
     * @return (Updatable) Map&lt;ParamName, ParamValue&gt; where a key value pair describes the specific action parameter. Example: `{&#34;count&#34;: &#34;3&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> actionParams() {
        return Optional.ofNullable(this.actionParams);
    }

    /**
     * The type of the scheduled action being performed
     * 
     */
    @Import(name="actionType", required=true)
    private Output<String> actionType;

    /**
     * @return The type of the scheduled action being performed
     * 
     */
    public Output<String> actionType() {
        return this.actionType;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Plan.
     * 
     */
    @Import(name="schedulingPlanId", required=true)
    private Output<String> schedulingPlanId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Plan.
     * 
     */
    public Output<String> schedulingPlanId() {
        return this.schedulingPlanId;
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Window.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="schedulingWindowId", required=true)
    private Output<String> schedulingWindowId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Window.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> schedulingWindowId() {
        return this.schedulingWindowId;
    }

    private ScheduledActionArgs() {}

    private ScheduledActionArgs(ScheduledActionArgs $) {
        this.actionMembers = $.actionMembers;
        this.actionParams = $.actionParams;
        this.actionType = $.actionType;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.freeformTags = $.freeformTags;
        this.schedulingPlanId = $.schedulingPlanId;
        this.schedulingWindowId = $.schedulingWindowId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ScheduledActionArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ScheduledActionArgs $;

        public Builder() {
            $ = new ScheduledActionArgs();
        }

        public Builder(ScheduledActionArgs defaults) {
            $ = new ScheduledActionArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param actionMembers (Updatable) The list of action members in a scheduled action.
         * 
         * @return builder
         * 
         */
        public Builder actionMembers(@Nullable Output<List<ScheduledActionActionMemberArgs>> actionMembers) {
            $.actionMembers = actionMembers;
            return this;
        }

        /**
         * @param actionMembers (Updatable) The list of action members in a scheduled action.
         * 
         * @return builder
         * 
         */
        public Builder actionMembers(List<ScheduledActionActionMemberArgs> actionMembers) {
            return actionMembers(Output.of(actionMembers));
        }

        /**
         * @param actionMembers (Updatable) The list of action members in a scheduled action.
         * 
         * @return builder
         * 
         */
        public Builder actionMembers(ScheduledActionActionMemberArgs... actionMembers) {
            return actionMembers(List.of(actionMembers));
        }

        /**
         * @param actionParams (Updatable) Map&lt;ParamName, ParamValue&gt; where a key value pair describes the specific action parameter. Example: `{&#34;count&#34;: &#34;3&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder actionParams(@Nullable Output<Map<String,String>> actionParams) {
            $.actionParams = actionParams;
            return this;
        }

        /**
         * @param actionParams (Updatable) Map&lt;ParamName, ParamValue&gt; where a key value pair describes the specific action parameter. Example: `{&#34;count&#34;: &#34;3&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder actionParams(Map<String,String> actionParams) {
            return actionParams(Output.of(actionParams));
        }

        /**
         * @param actionType The type of the scheduled action being performed
         * 
         * @return builder
         * 
         */
        public Builder actionType(Output<String> actionType) {
            $.actionType = actionType;
            return this;
        }

        /**
         * @param actionType The type of the scheduled action being performed
         * 
         * @return builder
         * 
         */
        public Builder actionType(String actionType) {
            return actionType(Output.of(actionType));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param freeformTags Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param schedulingPlanId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Plan.
         * 
         * @return builder
         * 
         */
        public Builder schedulingPlanId(Output<String> schedulingPlanId) {
            $.schedulingPlanId = schedulingPlanId;
            return this;
        }

        /**
         * @param schedulingPlanId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Plan.
         * 
         * @return builder
         * 
         */
        public Builder schedulingPlanId(String schedulingPlanId) {
            return schedulingPlanId(Output.of(schedulingPlanId));
        }

        /**
         * @param schedulingWindowId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Window.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder schedulingWindowId(Output<String> schedulingWindowId) {
            $.schedulingWindowId = schedulingWindowId;
            return this;
        }

        /**
         * @param schedulingWindowId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Window.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder schedulingWindowId(String schedulingWindowId) {
            return schedulingWindowId(Output.of(schedulingWindowId));
        }

        public ScheduledActionArgs build() {
            if ($.actionType == null) {
                throw new MissingRequiredPropertyException("ScheduledActionArgs", "actionType");
            }
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("ScheduledActionArgs", "compartmentId");
            }
            if ($.schedulingPlanId == null) {
                throw new MissingRequiredPropertyException("ScheduledActionArgs", "schedulingPlanId");
            }
            if ($.schedulingWindowId == null) {
                throw new MissingRequiredPropertyException("ScheduledActionArgs", "schedulingWindowId");
            }
            return $;
        }
    }

}
