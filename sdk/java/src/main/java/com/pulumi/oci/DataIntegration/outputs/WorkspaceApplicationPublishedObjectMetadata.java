// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class WorkspaceApplicationPublishedObjectMetadata {
    /**
     * @return The patch action indicating if object was created, updated, or deleted.
     * 
     */
    private @Nullable String action;
    /**
     * @return (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
     * 
     */
    private @Nullable String identifier;
    /**
     * @return The identifying key for the object.
     * 
     */
    private @Nullable String key;
    /**
     * @return (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
     * 
     */
    private @Nullable String name;
    /**
     * @return The fully qualified path of the published object, which would include its project and folder.
     * 
     */
    private @Nullable String namePath;
    /**
     * @return The object version.
     * 
     */
    private @Nullable Integer objectVersion;
    /**
     * @return The type of the object in patch.
     * 
     */
    private @Nullable String type;

    private WorkspaceApplicationPublishedObjectMetadata() {}
    /**
     * @return The patch action indicating if object was created, updated, or deleted.
     * 
     */
    public Optional<String> action() {
        return Optional.ofNullable(this.action);
    }
    /**
     * @return (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
     * 
     */
    public Optional<String> identifier() {
        return Optional.ofNullable(this.identifier);
    }
    /**
     * @return The identifying key for the object.
     * 
     */
    public Optional<String> key() {
        return Optional.ofNullable(this.key);
    }
    /**
     * @return (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return The fully qualified path of the published object, which would include its project and folder.
     * 
     */
    public Optional<String> namePath() {
        return Optional.ofNullable(this.namePath);
    }
    /**
     * @return The object version.
     * 
     */
    public Optional<Integer> objectVersion() {
        return Optional.ofNullable(this.objectVersion);
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

    public static Builder builder(WorkspaceApplicationPublishedObjectMetadata defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String action;
        private @Nullable String identifier;
        private @Nullable String key;
        private @Nullable String name;
        private @Nullable String namePath;
        private @Nullable Integer objectVersion;
        private @Nullable String type;
        public Builder() {}
        public Builder(WorkspaceApplicationPublishedObjectMetadata defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.action = defaults.action;
    	      this.identifier = defaults.identifier;
    	      this.key = defaults.key;
    	      this.name = defaults.name;
    	      this.namePath = defaults.namePath;
    	      this.objectVersion = defaults.objectVersion;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder action(@Nullable String action) {
            this.action = action;
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
        public Builder namePath(@Nullable String namePath) {
            this.namePath = namePath;
            return this;
        }
        @CustomType.Setter
        public Builder objectVersion(@Nullable Integer objectVersion) {
            this.objectVersion = objectVersion;
            return this;
        }
        @CustomType.Setter
        public Builder type(@Nullable String type) {
            this.type = type;
            return this;
        }
        public WorkspaceApplicationPublishedObjectMetadata build() {
            final var o = new WorkspaceApplicationPublishedObjectMetadata();
            o.action = action;
            o.identifier = identifier;
            o.key = key;
            o.name = name;
            o.namePath = namePath;
            o.objectVersion = objectVersion;
            o.type = type;
            return o;
        }
    }
}