// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Identity.outputs.GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionkerberosUserUserRealmUser;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionkerberosUserUser {
    /**
     * @return A list of kerberos realm users for an Oracle Identity Cloud Service User
     * 
     */
    private List<GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionkerberosUserUserRealmUser> realmUsers;

    private GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionkerberosUserUser() {}
    /**
     * @return A list of kerberos realm users for an Oracle Identity Cloud Service User
     * 
     */
    public List<GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionkerberosUserUserRealmUser> realmUsers() {
        return this.realmUsers;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionkerberosUserUser defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionkerberosUserUserRealmUser> realmUsers;
        public Builder() {}
        public Builder(GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionkerberosUserUser defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.realmUsers = defaults.realmUsers;
        }

        @CustomType.Setter
        public Builder realmUsers(List<GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionkerberosUserUserRealmUser> realmUsers) {
            if (realmUsers == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionkerberosUserUser", "realmUsers");
            }
            this.realmUsers = realmUsers;
            return this;
        }
        public Builder realmUsers(GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionkerberosUserUserRealmUser... realmUsers) {
            return realmUsers(List.of(realmUsers));
        }
        public GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionkerberosUserUser build() {
            final var _resultValue = new GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionkerberosUserUser();
            _resultValue.realmUsers = realmUsers;
            return _resultValue;
        }
    }
}
