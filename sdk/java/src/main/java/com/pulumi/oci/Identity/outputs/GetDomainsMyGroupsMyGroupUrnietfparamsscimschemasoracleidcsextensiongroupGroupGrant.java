// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsMyGroupsMyGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupGrant {
    /**
     * @return App identifier
     * 
     */
    private String appId;
    /**
     * @return Each value of grantMechanism indicates how (or by what component) some App (or App-Entitlement) was granted. A customer or the UI should use only grantMechanism values that start with &#39;ADMINISTRATOR&#39;:
     * * &#39;ADMINISTRATOR_TO_USER&#39; is for a direct grant to a specific User.
     * * &#39;ADMINISTRATOR_TO_GROUP&#39; is for a grant to a specific Group, which results in indirect grants to Users who are members of that Group.
     * * &#39;ADMINISTRATOR_TO_APP&#39; is for a grant to a specific App.  The grantee (client) App gains access to the granted (server) App.
     * 
     */
    private String grantMechanism;
    /**
     * @return App URI
     * 
     */
    private String ref;
    /**
     * @return The ID of the App.
     * 
     */
    private String value;

    private GetDomainsMyGroupsMyGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupGrant() {}
    /**
     * @return App identifier
     * 
     */
    public String appId() {
        return this.appId;
    }
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
     * @return App URI
     * 
     */
    public String ref() {
        return this.ref;
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

    public static Builder builder(GetDomainsMyGroupsMyGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupGrant defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String appId;
        private String grantMechanism;
        private String ref;
        private String value;
        public Builder() {}
        public Builder(GetDomainsMyGroupsMyGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupGrant defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.appId = defaults.appId;
    	      this.grantMechanism = defaults.grantMechanism;
    	      this.ref = defaults.ref;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder appId(String appId) {
            if (appId == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyGroupsMyGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupGrant", "appId");
            }
            this.appId = appId;
            return this;
        }
        @CustomType.Setter
        public Builder grantMechanism(String grantMechanism) {
            if (grantMechanism == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyGroupsMyGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupGrant", "grantMechanism");
            }
            this.grantMechanism = grantMechanism;
            return this;
        }
        @CustomType.Setter
        public Builder ref(String ref) {
            if (ref == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyGroupsMyGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupGrant", "ref");
            }
            this.ref = ref;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyGroupsMyGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupGrant", "value");
            }
            this.value = value;
            return this;
        }
        public GetDomainsMyGroupsMyGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupGrant build() {
            final var _resultValue = new GetDomainsMyGroupsMyGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupGrant();
            _resultValue.appId = appId;
            _resultValue.grantMechanism = grantMechanism;
            _resultValue.ref = ref;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
