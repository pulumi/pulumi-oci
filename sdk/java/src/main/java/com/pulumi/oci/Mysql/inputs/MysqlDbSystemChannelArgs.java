// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Mysql.inputs.MysqlDbSystemChannelSourceArgs;
import com.pulumi.oci.Mysql.inputs.MysqlDbSystemChannelTargetArgs;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MysqlDbSystemChannelArgs extends com.pulumi.resources.ResourceArgs {

    public static final MysqlDbSystemChannelArgs Empty = new MysqlDbSystemChannelArgs();

    /**
     * The OCID of the compartment.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The OCID of the compartment.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) The user-friendly name for the DB System. It does not have to be unique.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) The user-friendly name for the DB System. It does not have to be unique.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) Simple key-value pair applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * The OCID of the DB System.
     * 
     */
    @Import(name="id")
    private @Nullable Output<String> id;

    /**
     * @return The OCID of the DB System.
     * 
     */
    public Optional<Output<String>> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * (Updatable) Specifies if PITR is enabled or disabled.
     * 
     */
    @Import(name="isEnabled")
    private @Nullable Output<Boolean> isEnabled;

    /**
     * @return (Updatable) Specifies if PITR is enabled or disabled.
     * 
     */
    public Optional<Output<Boolean>> isEnabled() {
        return Optional.ofNullable(this.isEnabled);
    }

    /**
     * Additional information about the current lifecycleState.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return Additional information about the current lifecycleState.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * Parameters detailing how to provision the initial data of the system.
     * 
     */
    @Import(name="sources")
    private @Nullable Output<List<MysqlDbSystemChannelSourceArgs>> sources;

    /**
     * @return Parameters detailing how to provision the initial data of the system.
     * 
     */
    public Optional<Output<List<MysqlDbSystemChannelSourceArgs>>> sources() {
        return Optional.ofNullable(this.sources);
    }

    /**
     * (Updatable) The target state for the DB System. Could be set to `ACTIVE` or `INACTIVE`.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return (Updatable) The target state for the DB System. Could be set to `ACTIVE` or `INACTIVE`.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * Details about the Channel target.
     * 
     */
    @Import(name="targets")
    private @Nullable Output<List<MysqlDbSystemChannelTargetArgs>> targets;

    /**
     * @return Details about the Channel target.
     * 
     */
    public Optional<Output<List<MysqlDbSystemChannelTargetArgs>>> targets() {
        return Optional.ofNullable(this.targets);
    }

    /**
     * The date and time the DB System was created.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the DB System was created.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The time the DB System was last updated.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The time the DB System was last updated.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    private MysqlDbSystemChannelArgs() {}

    private MysqlDbSystemChannelArgs(MysqlDbSystemChannelArgs $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.id = $.id;
        this.isEnabled = $.isEnabled;
        this.lifecycleDetails = $.lifecycleDetails;
        this.sources = $.sources;
        this.state = $.state;
        this.targets = $.targets;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MysqlDbSystemChannelArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MysqlDbSystemChannelArgs $;

        public Builder() {
            $ = new MysqlDbSystemChannelArgs();
        }

        public Builder(MysqlDbSystemChannelArgs defaults) {
            $ = new MysqlDbSystemChannelArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) The user-friendly name for the DB System. It does not have to be unique.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) The user-friendly name for the DB System. It does not have to be unique.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param id The OCID of the DB System.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id The OCID of the DB System.
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        /**
         * @param isEnabled (Updatable) Specifies if PITR is enabled or disabled.
         * 
         * @return builder
         * 
         */
        public Builder isEnabled(@Nullable Output<Boolean> isEnabled) {
            $.isEnabled = isEnabled;
            return this;
        }

        /**
         * @param isEnabled (Updatable) Specifies if PITR is enabled or disabled.
         * 
         * @return builder
         * 
         */
        public Builder isEnabled(Boolean isEnabled) {
            return isEnabled(Output.of(isEnabled));
        }

        /**
         * @param lifecycleDetails Additional information about the current lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails Additional information about the current lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param sources Parameters detailing how to provision the initial data of the system.
         * 
         * @return builder
         * 
         */
        public Builder sources(@Nullable Output<List<MysqlDbSystemChannelSourceArgs>> sources) {
            $.sources = sources;
            return this;
        }

        /**
         * @param sources Parameters detailing how to provision the initial data of the system.
         * 
         * @return builder
         * 
         */
        public Builder sources(List<MysqlDbSystemChannelSourceArgs> sources) {
            return sources(Output.of(sources));
        }

        /**
         * @param sources Parameters detailing how to provision the initial data of the system.
         * 
         * @return builder
         * 
         */
        public Builder sources(MysqlDbSystemChannelSourceArgs... sources) {
            return sources(List.of(sources));
        }

        /**
         * @param state (Updatable) The target state for the DB System. Could be set to `ACTIVE` or `INACTIVE`.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state (Updatable) The target state for the DB System. Could be set to `ACTIVE` or `INACTIVE`.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param targets Details about the Channel target.
         * 
         * @return builder
         * 
         */
        public Builder targets(@Nullable Output<List<MysqlDbSystemChannelTargetArgs>> targets) {
            $.targets = targets;
            return this;
        }

        /**
         * @param targets Details about the Channel target.
         * 
         * @return builder
         * 
         */
        public Builder targets(List<MysqlDbSystemChannelTargetArgs> targets) {
            return targets(Output.of(targets));
        }

        /**
         * @param targets Details about the Channel target.
         * 
         * @return builder
         * 
         */
        public Builder targets(MysqlDbSystemChannelTargetArgs... targets) {
            return targets(List.of(targets));
        }

        /**
         * @param timeCreated The date and time the DB System was created.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the DB System was created.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The time the DB System was last updated.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The time the DB System was last updated.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        public MysqlDbSystemChannelArgs build() {
            return $;
        }
    }

}