// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.inputs.SchedulerDefinitionActionGroupArgs;
import com.pulumi.oci.FleetAppsManagement.inputs.SchedulerDefinitionRunBookArgs;
import com.pulumi.oci.FleetAppsManagement.inputs.SchedulerDefinitionScheduleArgs;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class SchedulerDefinitionArgs extends com.pulumi.resources.ResourceArgs {

    public static final SchedulerDefinitionArgs Empty = new SchedulerDefinitionArgs();

    /**
     * (Updatable) Action Groups associated with the Schedule.
     * 
     */
    @Import(name="actionGroups", required=true)
    private Output<List<SchedulerDefinitionActionGroupArgs>> actionGroups;

    /**
     * @return (Updatable) Action Groups associated with the Schedule.
     * 
     */
    public Output<List<SchedulerDefinitionActionGroupArgs>> actionGroups() {
        return this.actionGroups;
    }

    /**
     * Compartment OCID
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return Compartment OCID
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) Runbooks.
     * 
     */
    @Import(name="runBooks")
    private @Nullable Output<List<SchedulerDefinitionRunBookArgs>> runBooks;

    /**
     * @return (Updatable) Runbooks.
     * 
     */
    public Optional<Output<List<SchedulerDefinitionRunBookArgs>>> runBooks() {
        return Optional.ofNullable(this.runBooks);
    }

    /**
     * (Updatable) Schedule Information.
     * 
     */
    @Import(name="schedule", required=true)
    private Output<SchedulerDefinitionScheduleArgs> schedule;

    /**
     * @return (Updatable) Schedule Information.
     * 
     */
    public Output<SchedulerDefinitionScheduleArgs> schedule() {
        return this.schedule;
    }

    private SchedulerDefinitionArgs() {}

    private SchedulerDefinitionArgs(SchedulerDefinitionArgs $) {
        this.actionGroups = $.actionGroups;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.runBooks = $.runBooks;
        this.schedule = $.schedule;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(SchedulerDefinitionArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private SchedulerDefinitionArgs $;

        public Builder() {
            $ = new SchedulerDefinitionArgs();
        }

        public Builder(SchedulerDefinitionArgs defaults) {
            $ = new SchedulerDefinitionArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param actionGroups (Updatable) Action Groups associated with the Schedule.
         * 
         * @return builder
         * 
         */
        public Builder actionGroups(Output<List<SchedulerDefinitionActionGroupArgs>> actionGroups) {
            $.actionGroups = actionGroups;
            return this;
        }

        /**
         * @param actionGroups (Updatable) Action Groups associated with the Schedule.
         * 
         * @return builder
         * 
         */
        public Builder actionGroups(List<SchedulerDefinitionActionGroupArgs> actionGroups) {
            return actionGroups(Output.of(actionGroups));
        }

        /**
         * @param actionGroups (Updatable) Action Groups associated with the Schedule.
         * 
         * @return builder
         * 
         */
        public Builder actionGroups(SchedulerDefinitionActionGroupArgs... actionGroups) {
            return actionGroups(List.of(actionGroups));
        }

        /**
         * @param compartmentId Compartment OCID
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId Compartment OCID
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.  Example: `My new resource`
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param runBooks (Updatable) Runbooks.
         * 
         * @return builder
         * 
         */
        public Builder runBooks(@Nullable Output<List<SchedulerDefinitionRunBookArgs>> runBooks) {
            $.runBooks = runBooks;
            return this;
        }

        /**
         * @param runBooks (Updatable) Runbooks.
         * 
         * @return builder
         * 
         */
        public Builder runBooks(List<SchedulerDefinitionRunBookArgs> runBooks) {
            return runBooks(Output.of(runBooks));
        }

        /**
         * @param runBooks (Updatable) Runbooks.
         * 
         * @return builder
         * 
         */
        public Builder runBooks(SchedulerDefinitionRunBookArgs... runBooks) {
            return runBooks(List.of(runBooks));
        }

        /**
         * @param schedule (Updatable) Schedule Information.
         * 
         * @return builder
         * 
         */
        public Builder schedule(Output<SchedulerDefinitionScheduleArgs> schedule) {
            $.schedule = schedule;
            return this;
        }

        /**
         * @param schedule (Updatable) Schedule Information.
         * 
         * @return builder
         * 
         */
        public Builder schedule(SchedulerDefinitionScheduleArgs schedule) {
            return schedule(Output.of(schedule));
        }

        public SchedulerDefinitionArgs build() {
            if ($.actionGroups == null) {
                throw new MissingRequiredPropertyException("SchedulerDefinitionArgs", "actionGroups");
            }
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("SchedulerDefinitionArgs", "compartmentId");
            }
            if ($.schedule == null) {
                throw new MissingRequiredPropertyException("SchedulerDefinitionArgs", "schedule");
            }
            return $;
        }
    }

}
