// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetMigrationExcludeObject {
    /**
     * @return Name of the object (regular expression is allowed)
     * 
     */
    private String object;
    /**
     * @return Owner of the object (regular expression is allowed)
     * 
     */
    private String owner;
    /**
     * @return Migration type.
     * 
     */
    private String type;

    private GetMigrationExcludeObject() {}
    /**
     * @return Name of the object (regular expression is allowed)
     * 
     */
    public String object() {
        return this.object;
    }
    /**
     * @return Owner of the object (regular expression is allowed)
     * 
     */
    public String owner() {
        return this.owner;
    }
    /**
     * @return Migration type.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMigrationExcludeObject defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String object;
        private String owner;
        private String type;
        public Builder() {}
        public Builder(GetMigrationExcludeObject defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.object = defaults.object;
    	      this.owner = defaults.owner;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder object(String object) {
            this.object = Objects.requireNonNull(object);
            return this;
        }
        @CustomType.Setter
        public Builder owner(String owner) {
            this.owner = Objects.requireNonNull(owner);
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        public GetMigrationExcludeObject build() {
            final var o = new GetMigrationExcludeObject();
            o.object = object;
            o.owner = owner;
            o.type = type;
            return o;
        }
    }
}