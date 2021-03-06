// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseTools.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class DatabaseToolsConnectionRelatedResource {
    /**
     * @return (Updatable) The resource entity type.
     * 
     */
    private final String entityType;
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the related resource.
     * 
     */
    private final String identifier;

    @CustomType.Constructor
    private DatabaseToolsConnectionRelatedResource(
        @CustomType.Parameter("entityType") String entityType,
        @CustomType.Parameter("identifier") String identifier) {
        this.entityType = entityType;
        this.identifier = identifier;
    }

    /**
     * @return (Updatable) The resource entity type.
     * 
     */
    public String entityType() {
        return this.entityType;
    }
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the related resource.
     * 
     */
    public String identifier() {
        return this.identifier;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DatabaseToolsConnectionRelatedResource defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String entityType;
        private String identifier;

        public Builder() {
    	      // Empty
        }

        public Builder(DatabaseToolsConnectionRelatedResource defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.entityType = defaults.entityType;
    	      this.identifier = defaults.identifier;
        }

        public Builder entityType(String entityType) {
            this.entityType = Objects.requireNonNull(entityType);
            return this;
        }
        public Builder identifier(String identifier) {
            this.identifier = Objects.requireNonNull(identifier);
            return this;
        }        public DatabaseToolsConnectionRelatedResource build() {
            return new DatabaseToolsConnectionRelatedResource(entityType, identifier);
        }
    }
}
