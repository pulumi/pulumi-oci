// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class WorkspaceImportRequestImportedObject {
    /**
     * @return Aggregator key
     * 
     */
    private @Nullable String aggregatorKey;
    /**
     * @return Object identifier
     * 
     */
    private @Nullable String identifier;
    /**
     * @return Name of the import request.
     * 
     */
    private @Nullable String name;
    /**
     * @return Object name path
     * 
     */
    private @Nullable String namePath;
    /**
     * @return New key of the object
     * 
     */
    private @Nullable String newKey;
    /**
     * @return Object type
     * 
     */
    private @Nullable String objectType;
    /**
     * @return Object version
     * 
     */
    private @Nullable String objectVersion;
    /**
     * @return Old key of the object
     * 
     */
    private @Nullable String oldKey;
    /**
     * @return Object resolution action
     * 
     */
    private @Nullable String resolutionAction;
    /**
     * @return time at which this object was last updated.
     * 
     */
    private @Nullable String timeUpdatedInMillis;

    private WorkspaceImportRequestImportedObject() {}
    /**
     * @return Aggregator key
     * 
     */
    public Optional<String> aggregatorKey() {
        return Optional.ofNullable(this.aggregatorKey);
    }
    /**
     * @return Object identifier
     * 
     */
    public Optional<String> identifier() {
        return Optional.ofNullable(this.identifier);
    }
    /**
     * @return Name of the import request.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return Object name path
     * 
     */
    public Optional<String> namePath() {
        return Optional.ofNullable(this.namePath);
    }
    /**
     * @return New key of the object
     * 
     */
    public Optional<String> newKey() {
        return Optional.ofNullable(this.newKey);
    }
    /**
     * @return Object type
     * 
     */
    public Optional<String> objectType() {
        return Optional.ofNullable(this.objectType);
    }
    /**
     * @return Object version
     * 
     */
    public Optional<String> objectVersion() {
        return Optional.ofNullable(this.objectVersion);
    }
    /**
     * @return Old key of the object
     * 
     */
    public Optional<String> oldKey() {
        return Optional.ofNullable(this.oldKey);
    }
    /**
     * @return Object resolution action
     * 
     */
    public Optional<String> resolutionAction() {
        return Optional.ofNullable(this.resolutionAction);
    }
    /**
     * @return time at which this object was last updated.
     * 
     */
    public Optional<String> timeUpdatedInMillis() {
        return Optional.ofNullable(this.timeUpdatedInMillis);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(WorkspaceImportRequestImportedObject defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String aggregatorKey;
        private @Nullable String identifier;
        private @Nullable String name;
        private @Nullable String namePath;
        private @Nullable String newKey;
        private @Nullable String objectType;
        private @Nullable String objectVersion;
        private @Nullable String oldKey;
        private @Nullable String resolutionAction;
        private @Nullable String timeUpdatedInMillis;
        public Builder() {}
        public Builder(WorkspaceImportRequestImportedObject defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.aggregatorKey = defaults.aggregatorKey;
    	      this.identifier = defaults.identifier;
    	      this.name = defaults.name;
    	      this.namePath = defaults.namePath;
    	      this.newKey = defaults.newKey;
    	      this.objectType = defaults.objectType;
    	      this.objectVersion = defaults.objectVersion;
    	      this.oldKey = defaults.oldKey;
    	      this.resolutionAction = defaults.resolutionAction;
    	      this.timeUpdatedInMillis = defaults.timeUpdatedInMillis;
        }

        @CustomType.Setter
        public Builder aggregatorKey(@Nullable String aggregatorKey) {
            this.aggregatorKey = aggregatorKey;
            return this;
        }
        @CustomType.Setter
        public Builder identifier(@Nullable String identifier) {
            this.identifier = identifier;
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
        public Builder newKey(@Nullable String newKey) {
            this.newKey = newKey;
            return this;
        }
        @CustomType.Setter
        public Builder objectType(@Nullable String objectType) {
            this.objectType = objectType;
            return this;
        }
        @CustomType.Setter
        public Builder objectVersion(@Nullable String objectVersion) {
            this.objectVersion = objectVersion;
            return this;
        }
        @CustomType.Setter
        public Builder oldKey(@Nullable String oldKey) {
            this.oldKey = oldKey;
            return this;
        }
        @CustomType.Setter
        public Builder resolutionAction(@Nullable String resolutionAction) {
            this.resolutionAction = resolutionAction;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdatedInMillis(@Nullable String timeUpdatedInMillis) {
            this.timeUpdatedInMillis = timeUpdatedInMillis;
            return this;
        }
        public WorkspaceImportRequestImportedObject build() {
            final var o = new WorkspaceImportRequestImportedObject();
            o.aggregatorKey = aggregatorKey;
            o.identifier = identifier;
            o.name = name;
            o.namePath = namePath;
            o.newKey = newKey;
            o.objectType = objectType;
            o.objectVersion = objectVersion;
            o.oldKey = oldKey;
            o.resolutionAction = resolutionAction;
            o.timeUpdatedInMillis = timeUpdatedInMillis;
            return o;
        }
    }
}