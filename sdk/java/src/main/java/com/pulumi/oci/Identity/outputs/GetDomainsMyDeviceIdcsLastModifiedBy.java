// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsMyDeviceIdcsLastModifiedBy {
    /**
     * @return User display name
     * 
     */
    private String display;
    /**
     * @return The OCID of the user
     * 
     */
    private String ocid;
    /**
     * @return The URI that corresponds to the member Resource of this device
     * 
     */
    private String ref;
    /**
     * @return The type of resource, User or App, that modified this Resource
     * 
     */
    private String type;
    /**
     * @return The identifier of the user
     * 
     */
    private String value;

    private GetDomainsMyDeviceIdcsLastModifiedBy() {}
    /**
     * @return User display name
     * 
     */
    public String display() {
        return this.display;
    }
    /**
     * @return The OCID of the user
     * 
     */
    public String ocid() {
        return this.ocid;
    }
    /**
     * @return The URI that corresponds to the member Resource of this device
     * 
     */
    public String ref() {
        return this.ref;
    }
    /**
     * @return The type of resource, User or App, that modified this Resource
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return The identifier of the user
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsMyDeviceIdcsLastModifiedBy defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String display;
        private String ocid;
        private String ref;
        private String type;
        private String value;
        public Builder() {}
        public Builder(GetDomainsMyDeviceIdcsLastModifiedBy defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.display = defaults.display;
    	      this.ocid = defaults.ocid;
    	      this.ref = defaults.ref;
    	      this.type = defaults.type;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder display(String display) {
            this.display = Objects.requireNonNull(display);
            return this;
        }
        @CustomType.Setter
        public Builder ocid(String ocid) {
            this.ocid = Objects.requireNonNull(ocid);
            return this;
        }
        @CustomType.Setter
        public Builder ref(String ref) {
            this.ref = Objects.requireNonNull(ref);
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            this.value = Objects.requireNonNull(value);
            return this;
        }
        public GetDomainsMyDeviceIdcsLastModifiedBy build() {
            final var o = new GetDomainsMyDeviceIdcsLastModifiedBy();
            o.display = display;
            o.ocid = ocid;
            o.ref = ref;
            o.type = type;
            o.value = value;
            return o;
        }
    }
}