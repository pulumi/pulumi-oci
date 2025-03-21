// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetIamWorkRequestsIamWorkRequestResource {
    /**
     * @return The way in which this resource is affected by the work tracked in the work request. A resource being created, updated, or deleted will remain in the IN_PROGRESS state until work is complete for that resource at which point it will transition to CREATED, UPDATED, or DELETED, respectively.
     * 
     */
    private String actionType;
    /**
     * @return The resource type the work request is affects.
     * 
     */
    private String entityType;
    /**
     * @return The URI path that the user can do a GET on to access the resource metadata.
     * 
     */
    private String entityUri;
    /**
     * @return An OCID of the resource that the work request affects.
     * 
     */
    private String identifier;

    private GetIamWorkRequestsIamWorkRequestResource() {}
    /**
     * @return The way in which this resource is affected by the work tracked in the work request. A resource being created, updated, or deleted will remain in the IN_PROGRESS state until work is complete for that resource at which point it will transition to CREATED, UPDATED, or DELETED, respectively.
     * 
     */
    public String actionType() {
        return this.actionType;
    }
    /**
     * @return The resource type the work request is affects.
     * 
     */
    public String entityType() {
        return this.entityType;
    }
    /**
     * @return The URI path that the user can do a GET on to access the resource metadata.
     * 
     */
    public String entityUri() {
        return this.entityUri;
    }
    /**
     * @return An OCID of the resource that the work request affects.
     * 
     */
    public String identifier() {
        return this.identifier;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetIamWorkRequestsIamWorkRequestResource defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String actionType;
        private String entityType;
        private String entityUri;
        private String identifier;
        public Builder() {}
        public Builder(GetIamWorkRequestsIamWorkRequestResource defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.actionType = defaults.actionType;
    	      this.entityType = defaults.entityType;
    	      this.entityUri = defaults.entityUri;
    	      this.identifier = defaults.identifier;
        }

        @CustomType.Setter
        public Builder actionType(String actionType) {
            if (actionType == null) {
              throw new MissingRequiredPropertyException("GetIamWorkRequestsIamWorkRequestResource", "actionType");
            }
            this.actionType = actionType;
            return this;
        }
        @CustomType.Setter
        public Builder entityType(String entityType) {
            if (entityType == null) {
              throw new MissingRequiredPropertyException("GetIamWorkRequestsIamWorkRequestResource", "entityType");
            }
            this.entityType = entityType;
            return this;
        }
        @CustomType.Setter
        public Builder entityUri(String entityUri) {
            if (entityUri == null) {
              throw new MissingRequiredPropertyException("GetIamWorkRequestsIamWorkRequestResource", "entityUri");
            }
            this.entityUri = entityUri;
            return this;
        }
        @CustomType.Setter
        public Builder identifier(String identifier) {
            if (identifier == null) {
              throw new MissingRequiredPropertyException("GetIamWorkRequestsIamWorkRequestResource", "identifier");
            }
            this.identifier = identifier;
            return this;
        }
        public GetIamWorkRequestsIamWorkRequestResource build() {
            final var _resultValue = new GetIamWorkRequestsIamWorkRequestResource();
            _resultValue.actionType = actionType;
            _resultValue.entityType = entityType;
            _resultValue.entityUri = entityUri;
            _resultValue.identifier = identifier;
            return _resultValue;
        }
    }
}
