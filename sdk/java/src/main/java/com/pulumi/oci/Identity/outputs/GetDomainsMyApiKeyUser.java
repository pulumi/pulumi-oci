// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsMyApiKeyUser {
    /**
     * @return User display name
     * 
     */
    private String display;
    /**
     * @return User name
     * 
     */
    private String name;
    /**
     * @return User&#39;s ocid
     * 
     */
    private String ocid;
    /**
     * @return The URI that corresponds to the user linked to this credential
     * 
     */
    private String ref;
    /**
     * @return User&#39;s id
     * 
     */
    private String value;

    private GetDomainsMyApiKeyUser() {}
    /**
     * @return User display name
     * 
     */
    public String display() {
        return this.display;
    }
    /**
     * @return User name
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return User&#39;s ocid
     * 
     */
    public String ocid() {
        return this.ocid;
    }
    /**
     * @return The URI that corresponds to the user linked to this credential
     * 
     */
    public String ref() {
        return this.ref;
    }
    /**
     * @return User&#39;s id
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsMyApiKeyUser defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String display;
        private String name;
        private String ocid;
        private String ref;
        private String value;
        public Builder() {}
        public Builder(GetDomainsMyApiKeyUser defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.display = defaults.display;
    	      this.name = defaults.name;
    	      this.ocid = defaults.ocid;
    	      this.ref = defaults.ref;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder display(String display) {
            this.display = Objects.requireNonNull(display);
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
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
        public Builder value(String value) {
            this.value = Objects.requireNonNull(value);
            return this;
        }
        public GetDomainsMyApiKeyUser build() {
            final var o = new GetDomainsMyApiKeyUser();
            o.display = display;
            o.name = name;
            o.ocid = ocid;
            o.ref = ref;
            o.value = value;
            return o;
        }
    }
}