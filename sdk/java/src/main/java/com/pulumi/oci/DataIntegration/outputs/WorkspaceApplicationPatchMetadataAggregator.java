// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class WorkspaceApplicationPatchMetadataAggregator {
    /**
     * @return Detailed description for the object.
     * 
     */
    private @Nullable String description;
    /**
     * @return Value can only contain upper case letters, underscore and numbers. It should begin with upper case letter or underscore. The value can be modified.
     * 
     */
    private @Nullable String identifier;
    /**
     * @return The object&#39;s key.
     * 
     */
    private @Nullable String key;
    /**
     * @return Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
     * 
     */
    private @Nullable String name;
    /**
     * @return The type of the object in patch.
     * 
     */
    private @Nullable String type;

    private WorkspaceApplicationPatchMetadataAggregator() {}
    /**
     * @return Detailed description for the object.
     * 
     */
    public Optional<String> description() {
        return Optional.ofNullable(this.description);
    }
    /**
     * @return Value can only contain upper case letters, underscore and numbers. It should begin with upper case letter or underscore. The value can be modified.
     * 
     */
    public Optional<String> identifier() {
        return Optional.ofNullable(this.identifier);
    }
    /**
     * @return The object&#39;s key.
     * 
     */
    public Optional<String> key() {
        return Optional.ofNullable(this.key);
    }
    /**
     * @return Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return The type of the object in patch.
     * 
     */
    public Optional<String> type() {
        return Optional.ofNullable(this.type);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(WorkspaceApplicationPatchMetadataAggregator defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String description;
        private @Nullable String identifier;
        private @Nullable String key;
        private @Nullable String name;
        private @Nullable String type;
        public Builder() {}
        public Builder(WorkspaceApplicationPatchMetadataAggregator defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.description = defaults.description;
    	      this.identifier = defaults.identifier;
    	      this.key = defaults.key;
    	      this.name = defaults.name;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder description(@Nullable String description) {

            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder identifier(@Nullable String identifier) {

            this.identifier = identifier;
            return this;
        }
        @CustomType.Setter
        public Builder key(@Nullable String key) {

            this.key = key;
            return this;
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {

            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder type(@Nullable String type) {

            this.type = type;
            return this;
        }
        public WorkspaceApplicationPatchMetadataAggregator build() {
            final var _resultValue = new WorkspaceApplicationPatchMetadataAggregator();
            _resultValue.description = description;
            _resultValue.identifier = identifier;
            _resultValue.key = key;
            _resultValue.name = name;
            _resultValue.type = type;
            return _resultValue;
        }
    }
}
