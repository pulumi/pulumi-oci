// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Database.outputs.AutonomousDatabaseConnectionStringProfile;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class AutonomousDatabaseConnectionString {
    /**
     * @return Returns all connection strings that can be used to connect to the Autonomous Database. For more information, please see [Predefined Database Service Names for Autonomous Transaction Processing](https://docs.oracle.com/en/cloud/paas/atp-cloud/atpug/connect-predefined.html#GUID-9747539B-FD46-44F1-8FF8-F5AC650F15BE)
     * 
     */
    private final @Nullable Map<String,Object> allConnectionStrings;
    /**
     * @return The database service provides the least level of resources to each SQL statement, but supports the most number of concurrent SQL statements.
     * 
     */
    private final @Nullable String dedicated;
    /**
     * @return The High database service provides the highest level of resources to each SQL statement resulting in the highest performance, but supports the fewest number of concurrent SQL statements.
     * 
     */
    private final @Nullable String high;
    /**
     * @return The Low database service provides the least level of resources to each SQL statement, but supports the most number of concurrent SQL statements.
     * 
     */
    private final @Nullable String low;
    /**
     * @return The Medium database service provides a lower level of resources to each SQL statement potentially resulting a lower level of performance, but supports more concurrent SQL statements.
     * 
     */
    private final @Nullable String medium;
    /**
     * @return A list of connection string profiles to allow clients to group, filter and select connection string values based on structured metadata.
     * 
     */
    private final @Nullable List<AutonomousDatabaseConnectionStringProfile> profiles;

    @CustomType.Constructor
    private AutonomousDatabaseConnectionString(
        @CustomType.Parameter("allConnectionStrings") @Nullable Map<String,Object> allConnectionStrings,
        @CustomType.Parameter("dedicated") @Nullable String dedicated,
        @CustomType.Parameter("high") @Nullable String high,
        @CustomType.Parameter("low") @Nullable String low,
        @CustomType.Parameter("medium") @Nullable String medium,
        @CustomType.Parameter("profiles") @Nullable List<AutonomousDatabaseConnectionStringProfile> profiles) {
        this.allConnectionStrings = allConnectionStrings;
        this.dedicated = dedicated;
        this.high = high;
        this.low = low;
        this.medium = medium;
        this.profiles = profiles;
    }

    /**
     * @return Returns all connection strings that can be used to connect to the Autonomous Database. For more information, please see [Predefined Database Service Names for Autonomous Transaction Processing](https://docs.oracle.com/en/cloud/paas/atp-cloud/atpug/connect-predefined.html#GUID-9747539B-FD46-44F1-8FF8-F5AC650F15BE)
     * 
     */
    public Map<String,Object> allConnectionStrings() {
        return this.allConnectionStrings == null ? Map.of() : this.allConnectionStrings;
    }
    /**
     * @return The database service provides the least level of resources to each SQL statement, but supports the most number of concurrent SQL statements.
     * 
     */
    public Optional<String> dedicated() {
        return Optional.ofNullable(this.dedicated);
    }
    /**
     * @return The High database service provides the highest level of resources to each SQL statement resulting in the highest performance, but supports the fewest number of concurrent SQL statements.
     * 
     */
    public Optional<String> high() {
        return Optional.ofNullable(this.high);
    }
    /**
     * @return The Low database service provides the least level of resources to each SQL statement, but supports the most number of concurrent SQL statements.
     * 
     */
    public Optional<String> low() {
        return Optional.ofNullable(this.low);
    }
    /**
     * @return The Medium database service provides a lower level of resources to each SQL statement potentially resulting a lower level of performance, but supports more concurrent SQL statements.
     * 
     */
    public Optional<String> medium() {
        return Optional.ofNullable(this.medium);
    }
    /**
     * @return A list of connection string profiles to allow clients to group, filter and select connection string values based on structured metadata.
     * 
     */
    public List<AutonomousDatabaseConnectionStringProfile> profiles() {
        return this.profiles == null ? List.of() : this.profiles;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(AutonomousDatabaseConnectionString defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable Map<String,Object> allConnectionStrings;
        private @Nullable String dedicated;
        private @Nullable String high;
        private @Nullable String low;
        private @Nullable String medium;
        private @Nullable List<AutonomousDatabaseConnectionStringProfile> profiles;

        public Builder() {
    	      // Empty
        }

        public Builder(AutonomousDatabaseConnectionString defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.allConnectionStrings = defaults.allConnectionStrings;
    	      this.dedicated = defaults.dedicated;
    	      this.high = defaults.high;
    	      this.low = defaults.low;
    	      this.medium = defaults.medium;
    	      this.profiles = defaults.profiles;
        }

        public Builder allConnectionStrings(@Nullable Map<String,Object> allConnectionStrings) {
            this.allConnectionStrings = allConnectionStrings;
            return this;
        }
        public Builder dedicated(@Nullable String dedicated) {
            this.dedicated = dedicated;
            return this;
        }
        public Builder high(@Nullable String high) {
            this.high = high;
            return this;
        }
        public Builder low(@Nullable String low) {
            this.low = low;
            return this;
        }
        public Builder medium(@Nullable String medium) {
            this.medium = medium;
            return this;
        }
        public Builder profiles(@Nullable List<AutonomousDatabaseConnectionStringProfile> profiles) {
            this.profiles = profiles;
            return this;
        }
        public Builder profiles(AutonomousDatabaseConnectionStringProfile... profiles) {
            return profiles(List.of(profiles));
        }        public AutonomousDatabaseConnectionString build() {
            return new AutonomousDatabaseConnectionString(allConnectionStrings, dedicated, high, low, medium, profiles);
        }
    }
}
