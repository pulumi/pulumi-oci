// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetMigrationsMigrationCollectionItemGoldenGateDetailHubTargetDbAdminCredential {
    private final String password;
    /**
     * @return Administrator username
     * 
     */
    private final String username;

    @CustomType.Constructor
    private GetMigrationsMigrationCollectionItemGoldenGateDetailHubTargetDbAdminCredential(
        @CustomType.Parameter("password") String password,
        @CustomType.Parameter("username") String username) {
        this.password = password;
        this.username = username;
    }

    public String password() {
        return this.password;
    }
    /**
     * @return Administrator username
     * 
     */
    public String username() {
        return this.username;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMigrationsMigrationCollectionItemGoldenGateDetailHubTargetDbAdminCredential defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String password;
        private String username;

        public Builder() {
    	      // Empty
        }

        public Builder(GetMigrationsMigrationCollectionItemGoldenGateDetailHubTargetDbAdminCredential defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.password = defaults.password;
    	      this.username = defaults.username;
        }

        public Builder password(String password) {
            this.password = Objects.requireNonNull(password);
            return this;
        }
        public Builder username(String username) {
            this.username = Objects.requireNonNull(username);
            return this;
        }        public GetMigrationsMigrationCollectionItemGoldenGateDetailHubTargetDbAdminCredential build() {
            return new GetMigrationsMigrationCollectionItemGoldenGateDetailHubTargetDbAdminCredential(password, username);
        }
    }
}
