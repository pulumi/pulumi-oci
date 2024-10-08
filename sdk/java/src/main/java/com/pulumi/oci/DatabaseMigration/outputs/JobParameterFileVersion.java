// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class JobParameterFileVersion {
    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private @Nullable Map<String,String> definedTags;
    /**
     * @return A description to discribe the current parameter file version
     * 
     */
    private @Nullable String description;
    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.  For more information, see Resource Tags. Example: {&#34;Department&#34;: &#34;Finance&#34;}
     * 
     */
    private @Nullable Map<String,String> freeformTags;
    /**
     * @return Return boolean true/false for the currently in-use parameter file (factory or a versioned file)
     * 
     */
    private @Nullable Boolean isCurrent;
    /**
     * @return Return true/false for whether the parameter file is oracle provided (Factory)
     * 
     */
    private @Nullable Boolean isFactory;
    /**
     * @return Indicator of Parameter File &#39;kind&#39; (for an EXTRACT or a REPLICAT)
     * 
     */
    private @Nullable String kind;
    /**
     * @return Phase name
     * 
     */
    private @Nullable String name;
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private @Nullable Map<String,String> systemTags;
    /**
     * @return The time the Migration Job was created. An RFC3339 formatted datetime string
     * 
     */
    private @Nullable String timeCreated;

    private JobParameterFileVersion() {}
    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags == null ? Map.of() : this.definedTags;
    }
    /**
     * @return A description to discribe the current parameter file version
     * 
     */
    public Optional<String> description() {
        return Optional.ofNullable(this.description);
    }
    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.  For more information, see Resource Tags. Example: {&#34;Department&#34;: &#34;Finance&#34;}
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags == null ? Map.of() : this.freeformTags;
    }
    /**
     * @return Return boolean true/false for the currently in-use parameter file (factory or a versioned file)
     * 
     */
    public Optional<Boolean> isCurrent() {
        return Optional.ofNullable(this.isCurrent);
    }
    /**
     * @return Return true/false for whether the parameter file is oracle provided (Factory)
     * 
     */
    public Optional<Boolean> isFactory() {
        return Optional.ofNullable(this.isFactory);
    }
    /**
     * @return Indicator of Parameter File &#39;kind&#39; (for an EXTRACT or a REPLICAT)
     * 
     */
    public Optional<String> kind() {
        return Optional.ofNullable(this.kind);
    }
    /**
     * @return Phase name
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,String> systemTags() {
        return this.systemTags == null ? Map.of() : this.systemTags;
    }
    /**
     * @return The time the Migration Job was created. An RFC3339 formatted datetime string
     * 
     */
    public Optional<String> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(JobParameterFileVersion defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Map<String,String> definedTags;
        private @Nullable String description;
        private @Nullable Map<String,String> freeformTags;
        private @Nullable Boolean isCurrent;
        private @Nullable Boolean isFactory;
        private @Nullable String kind;
        private @Nullable String name;
        private @Nullable Map<String,String> systemTags;
        private @Nullable String timeCreated;
        public Builder() {}
        public Builder(JobParameterFileVersion defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.freeformTags = defaults.freeformTags;
    	      this.isCurrent = defaults.isCurrent;
    	      this.isFactory = defaults.isFactory;
    	      this.kind = defaults.kind;
    	      this.name = defaults.name;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
        }

        @CustomType.Setter
        public Builder definedTags(@Nullable Map<String,String> definedTags) {

            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder description(@Nullable String description) {

            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(@Nullable Map<String,String> freeformTags) {

            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder isCurrent(@Nullable Boolean isCurrent) {

            this.isCurrent = isCurrent;
            return this;
        }
        @CustomType.Setter
        public Builder isFactory(@Nullable Boolean isFactory) {

            this.isFactory = isFactory;
            return this;
        }
        @CustomType.Setter
        public Builder kind(@Nullable String kind) {

            this.kind = kind;
            return this;
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {

            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(@Nullable Map<String,String> systemTags) {

            this.systemTags = systemTags;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(@Nullable String timeCreated) {

            this.timeCreated = timeCreated;
            return this;
        }
        public JobParameterFileVersion build() {
            final var _resultValue = new JobParameterFileVersion();
            _resultValue.definedTags = definedTags;
            _resultValue.description = description;
            _resultValue.freeformTags = freeformTags;
            _resultValue.isCurrent = isCurrent;
            _resultValue.isFactory = isFactory;
            _resultValue.kind = kind;
            _resultValue.name = name;
            _resultValue.systemTags = systemTags;
            _resultValue.timeCreated = timeCreated;
            return _resultValue;
        }
    }
}
