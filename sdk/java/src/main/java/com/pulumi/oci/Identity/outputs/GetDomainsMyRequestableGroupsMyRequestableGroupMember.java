// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsMyRequestableGroupsMyRequestableGroupMember {
    /**
     * @return The date and time that the member was added to the group.
     * 
     */
    private String dateAdded;
    /**
     * @return App Display Name
     * 
     */
    private String display;
    /**
     * @return The membership OCID.
     * 
     */
    private String membershipOcid;
    /**
     * @return PasswordPolicy Name
     * 
     */
    private String name;
    /**
     * @return Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     * 
     */
    private String ocid;
    /**
     * @return App URI
     * 
     */
    private String ref;
    /**
     * @return The type of the entity that created this Group.
     * 
     */
    private String type;
    /**
     * @return The ID of the App.
     * 
     */
    private String value;

    private GetDomainsMyRequestableGroupsMyRequestableGroupMember() {}
    /**
     * @return The date and time that the member was added to the group.
     * 
     */
    public String dateAdded() {
        return this.dateAdded;
    }
    /**
     * @return App Display Name
     * 
     */
    public String display() {
        return this.display;
    }
    /**
     * @return The membership OCID.
     * 
     */
    public String membershipOcid() {
        return this.membershipOcid;
    }
    /**
     * @return PasswordPolicy Name
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     * 
     */
    public String ocid() {
        return this.ocid;
    }
    /**
     * @return App URI
     * 
     */
    public String ref() {
        return this.ref;
    }
    /**
     * @return The type of the entity that created this Group.
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return The ID of the App.
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsMyRequestableGroupsMyRequestableGroupMember defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String dateAdded;
        private String display;
        private String membershipOcid;
        private String name;
        private String ocid;
        private String ref;
        private String type;
        private String value;
        public Builder() {}
        public Builder(GetDomainsMyRequestableGroupsMyRequestableGroupMember defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.dateAdded = defaults.dateAdded;
    	      this.display = defaults.display;
    	      this.membershipOcid = defaults.membershipOcid;
    	      this.name = defaults.name;
    	      this.ocid = defaults.ocid;
    	      this.ref = defaults.ref;
    	      this.type = defaults.type;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder dateAdded(String dateAdded) {
            this.dateAdded = Objects.requireNonNull(dateAdded);
            return this;
        }
        @CustomType.Setter
        public Builder display(String display) {
            this.display = Objects.requireNonNull(display);
            return this;
        }
        @CustomType.Setter
        public Builder membershipOcid(String membershipOcid) {
            this.membershipOcid = Objects.requireNonNull(membershipOcid);
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
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            this.value = Objects.requireNonNull(value);
            return this;
        }
        public GetDomainsMyRequestableGroupsMyRequestableGroupMember build() {
            final var o = new GetDomainsMyRequestableGroupsMyRequestableGroupMember();
            o.dateAdded = dateAdded;
            o.display = display;
            o.membershipOcid = membershipOcid;
            o.name = name;
            o.ocid = ocid;
            o.ref = ref;
            o.type = type;
            o.value = value;
            return o;
        }
    }
}