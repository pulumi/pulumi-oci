// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Mysql.outputs.MysqlDbSystemChannelSource;
import com.pulumi.oci.Mysql.outputs.MysqlDbSystemChannelTarget;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class MysqlDbSystemChannel {
    /**
     * @return The OCID of the compartment.
     * 
     */
    private @Nullable String compartmentId;
    /**
     * @return (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private @Nullable Map<String,String> definedTags;
    /**
     * @return (Updatable) The user-friendly name for the DB System. It does not have to be unique.
     * 
     */
    private @Nullable String displayName;
    /**
     * @return (Updatable) Simple key-value pair applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private @Nullable Map<String,String> freeformTags;
    /**
     * @return The OCID of the DB System.
     * 
     */
    private @Nullable String id;
    /**
     * @return Specifies if the DB System read endpoint is enabled or not.
     * 
     */
    private @Nullable Boolean isEnabled;
    /**
     * @return Additional information about the current lifecycleState.
     * 
     */
    private @Nullable String lifecycleDetails;
    /**
     * @return Parameters detailing how to provision the initial data of the system.
     * 
     */
    private @Nullable List<MysqlDbSystemChannelSource> sources;
    /**
     * @return (Updatable) The target state for the DB System. Could be set to `ACTIVE` or `INACTIVE`.
     * 
     */
    private @Nullable String state;
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private @Nullable Map<String,String> systemTags;
    /**
     * @return Details about the Channel target.
     * 
     */
    private @Nullable List<MysqlDbSystemChannelTarget> targets;
    /**
     * @return The date and time the DB System was created.
     * 
     */
    private @Nullable String timeCreated;
    /**
     * @return The time the DB System was last updated.
     * 
     */
    private @Nullable String timeUpdated;

    private MysqlDbSystemChannel() {}
    /**
     * @return The OCID of the compartment.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    /**
     * @return (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags == null ? Map.of() : this.definedTags;
    }
    /**
     * @return (Updatable) The user-friendly name for the DB System. It does not have to be unique.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return (Updatable) Simple key-value pair applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags == null ? Map.of() : this.freeformTags;
    }
    /**
     * @return The OCID of the DB System.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return Specifies if the DB System read endpoint is enabled or not.
     * 
     */
    public Optional<Boolean> isEnabled() {
        return Optional.ofNullable(this.isEnabled);
    }
    /**
     * @return Additional information about the current lifecycleState.
     * 
     */
    public Optional<String> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }
    /**
     * @return Parameters detailing how to provision the initial data of the system.
     * 
     */
    public List<MysqlDbSystemChannelSource> sources() {
        return this.sources == null ? List.of() : this.sources;
    }
    /**
     * @return (Updatable) The target state for the DB System. Could be set to `ACTIVE` or `INACTIVE`.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags == null ? Map.of() : this.systemTags;
    }
    /**
     * @return Details about the Channel target.
     * 
     */
    public List<MysqlDbSystemChannelTarget> targets() {
        return this.targets == null ? List.of() : this.targets;
    }
    /**
     * @return The date and time the DB System was created.
     * 
     */
    public Optional<String> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }
    /**
     * @return The time the DB System was last updated.
     * 
     */
    public Optional<String> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(MysqlDbSystemChannel defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String compartmentId;
        private @Nullable Map<String,String> definedTags;
        private @Nullable String displayName;
        private @Nullable Map<String,String> freeformTags;
        private @Nullable String id;
        private @Nullable Boolean isEnabled;
        private @Nullable String lifecycleDetails;
        private @Nullable List<MysqlDbSystemChannelSource> sources;
        private @Nullable String state;
        private @Nullable Map<String,String> systemTags;
        private @Nullable List<MysqlDbSystemChannelTarget> targets;
        private @Nullable String timeCreated;
        private @Nullable String timeUpdated;
        public Builder() {}
        public Builder(MysqlDbSystemChannel defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.isEnabled = defaults.isEnabled;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.sources = defaults.sources;
    	      this.state = defaults.state;
    	      this.systemTags = defaults.systemTags;
    	      this.targets = defaults.targets;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder compartmentId(@Nullable String compartmentId) {

            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(@Nullable Map<String,String> definedTags) {

            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(@Nullable Map<String,String> freeformTags) {

            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {

            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isEnabled(@Nullable Boolean isEnabled) {

            this.isEnabled = isEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(@Nullable String lifecycleDetails) {

            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder sources(@Nullable List<MysqlDbSystemChannelSource> sources) {

            this.sources = sources;
            return this;
        }
        public Builder sources(MysqlDbSystemChannelSource... sources) {
            return sources(List.of(sources));
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(@Nullable Map<String,String> systemTags) {

            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder targets(@Nullable List<MysqlDbSystemChannelTarget> targets) {

            this.targets = targets;
            return this;
        }
        public Builder targets(MysqlDbSystemChannelTarget... targets) {
            return targets(List.of(targets));
        }
        @CustomType.Setter
        public Builder timeCreated(@Nullable String timeCreated) {

            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(@Nullable String timeUpdated) {

            this.timeUpdated = timeUpdated;
            return this;
        }
        public MysqlDbSystemChannel build() {
            final var _resultValue = new MysqlDbSystemChannel();
            _resultValue.compartmentId = compartmentId;
            _resultValue.definedTags = definedTags;
            _resultValue.displayName = displayName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.isEnabled = isEnabled;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.sources = sources;
            _resultValue.state = state;
            _resultValue.systemTags = systemTags;
            _resultValue.targets = targets;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
