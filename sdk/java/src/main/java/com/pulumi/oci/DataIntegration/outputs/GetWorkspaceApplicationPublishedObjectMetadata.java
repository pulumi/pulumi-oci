// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetWorkspaceApplicationPublishedObjectMetadata {
    /**
     * @return The patch action indicating if object was created, updated, or deleted.
     * 
     */
    private String action;
    /**
     * @return Value can only contain upper case letters, underscore and numbers. It should begin with upper case letter or underscore. The value can be modified.
     * 
     */
    private String identifier;
    /**
     * @return The key of the object.
     * 
     */
    private String key;
    /**
     * @return Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
     * 
     */
    private String name;
    /**
     * @return The fully qualified path of the published object, which would include its project and folder.
     * 
     */
    private String namePath;
    /**
     * @return The object version.
     * 
     */
    private Integer objectVersion;
    /**
     * @return The type of the object in patch.
     * 
     */
    private String type;

    private GetWorkspaceApplicationPublishedObjectMetadata() {}
    /**
     * @return The patch action indicating if object was created, updated, or deleted.
     * 
     */
    public String action() {
        return this.action;
    }
    /**
     * @return Value can only contain upper case letters, underscore and numbers. It should begin with upper case letter or underscore. The value can be modified.
     * 
     */
    public String identifier() {
        return this.identifier;
    }
    /**
     * @return The key of the object.
     * 
     */
    public String key() {
        return this.key;
    }
    /**
     * @return Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The fully qualified path of the published object, which would include its project and folder.
     * 
     */
    public String namePath() {
        return this.namePath;
    }
    /**
     * @return The object version.
     * 
     */
    public Integer objectVersion() {
        return this.objectVersion;
    }
    /**
     * @return The type of the object in patch.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkspaceApplicationPublishedObjectMetadata defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String action;
        private String identifier;
        private String key;
        private String name;
        private String namePath;
        private Integer objectVersion;
        private String type;
        public Builder() {}
        public Builder(GetWorkspaceApplicationPublishedObjectMetadata defaults) {
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
        public Builder action(String action) {
            this.action = Objects.requireNonNull(action);
            return this;
        }
        @CustomType.Setter
        public Builder identifier(String identifier) {
            this.identifier = Objects.requireNonNull(identifier);
            return this;
        }
        @CustomType.Setter
        public Builder key(String key) {
            this.key = Objects.requireNonNull(key);
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        @CustomType.Setter
        public Builder namePath(String namePath) {
            this.namePath = Objects.requireNonNull(namePath);
            return this;
        }
        @CustomType.Setter
        public Builder objectVersion(Integer objectVersion) {
            this.objectVersion = Objects.requireNonNull(objectVersion);
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        public GetWorkspaceApplicationPublishedObjectMetadata build() {
            final var o = new GetWorkspaceApplicationPublishedObjectMetadata();
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