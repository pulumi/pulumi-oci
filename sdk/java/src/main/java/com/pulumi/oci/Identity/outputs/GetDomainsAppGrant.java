// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsAppGrant {
    /**
     * @return Each value of grantMechanism indicates how (or by what component) some App (or App-Entitlement) was granted. A customer or the UI should use only grantMechanism values that start with &#39;ADMINISTRATOR&#39;:
     * * &#39;ADMINISTRATOR_TO_USER&#39; is for a direct grant to a specific User.
     * * &#39;ADMINISTRATOR_TO_GROUP&#39; is for a grant to a specific Group, which results in indirect grants to Users who are members of that Group.
     * * &#39;ADMINISTRATOR_TO_APP&#39; is for a grant to a specific App.  The grantee (client) App gains access to the granted (server) App.
     * 
     */
    private String grantMechanism;
    /**
     * @return Grantee identifier
     * 
     */
    private String granteeId;
    /**
     * @return Grantee resource type. Allowed values are User and Group.
     * 
     */
    private String granteeType;
    /**
     * @return URI of the AppRole.
     * 
     */
    private String ref;
    /**
     * @return ID of the AppRole.
     * 
     */
    private String value;

    private GetDomainsAppGrant() {}
    /**
     * @return Each value of grantMechanism indicates how (or by what component) some App (or App-Entitlement) was granted. A customer or the UI should use only grantMechanism values that start with &#39;ADMINISTRATOR&#39;:
     * * &#39;ADMINISTRATOR_TO_USER&#39; is for a direct grant to a specific User.
     * * &#39;ADMINISTRATOR_TO_GROUP&#39; is for a grant to a specific Group, which results in indirect grants to Users who are members of that Group.
     * * &#39;ADMINISTRATOR_TO_APP&#39; is for a grant to a specific App.  The grantee (client) App gains access to the granted (server) App.
     * 
     */
    public String grantMechanism() {
        return this.grantMechanism;
    }
    /**
     * @return Grantee identifier
     * 
     */
    public String granteeId() {
        return this.granteeId;
    }
    /**
     * @return Grantee resource type. Allowed values are User and Group.
     * 
     */
    public String granteeType() {
        return this.granteeType;
    }
    /**
     * @return URI of the AppRole.
     * 
     */
    public String ref() {
        return this.ref;
    }
    /**
     * @return ID of the AppRole.
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsAppGrant defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String grantMechanism;
        private String granteeId;
        private String granteeType;
        private String ref;
        private String value;
        public Builder() {}
        public Builder(GetDomainsAppGrant defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.grantMechanism = defaults.grantMechanism;
    	      this.granteeId = defaults.granteeId;
    	      this.granteeType = defaults.granteeType;
    	      this.ref = defaults.ref;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder grantMechanism(String grantMechanism) {
            if (grantMechanism == null) {
              throw new MissingRequiredPropertyException("GetDomainsAppGrant", "grantMechanism");
            }
            this.grantMechanism = grantMechanism;
            return this;
        }
        @CustomType.Setter
        public Builder granteeId(String granteeId) {
            if (granteeId == null) {
              throw new MissingRequiredPropertyException("GetDomainsAppGrant", "granteeId");
            }
            this.granteeId = granteeId;
            return this;
        }
        @CustomType.Setter
        public Builder granteeType(String granteeType) {
            if (granteeType == null) {
              throw new MissingRequiredPropertyException("GetDomainsAppGrant", "granteeType");
            }
            this.granteeType = granteeType;
            return this;
        }
        @CustomType.Setter
        public Builder ref(String ref) {
            if (ref == null) {
              throw new MissingRequiredPropertyException("GetDomainsAppGrant", "ref");
            }
            this.ref = ref;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("GetDomainsAppGrant", "value");
            }
            this.value = value;
            return this;
        }
        public GetDomainsAppGrant build() {
            final var _resultValue = new GetDomainsAppGrant();
            _resultValue.grantMechanism = grantMechanism;
            _resultValue.granteeId = granteeId;
            _resultValue.granteeType = granteeType;
            _resultValue.ref = ref;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
