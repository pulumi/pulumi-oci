// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Database.outputs.GetAutonomousDatabasesClonesAutonomousDatabaseConnectionStringProfile;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetAutonomousDatabasesClonesAutonomousDatabaseConnectionString {
    /**
     * @return Returns all connection strings that can be used to connect to the Autonomous Database. For more information, please see [Predefined Database Service Names for Autonomous Transaction Processing](https://docs.oracle.com/en/cloud/paas/atp-cloud/atpug/connect-predefined.html#GUID-9747539B-FD46-44F1-8FF8-F5AC650F15BE)
     * 
     */
    private final Map<String,Object> allConnectionStrings;
    /**
     * @return The database service provides the least level of resources to each SQL statement, but supports the most number of concurrent SQL statements.
     * 
     */
    private final String dedicated;
    /**
     * @return The High database service provides the highest level of resources to each SQL statement resulting in the highest performance, but supports the fewest number of concurrent SQL statements.
     * 
     */
    private final String high;
    /**
     * @return The Low database service provides the least level of resources to each SQL statement, but supports the most number of concurrent SQL statements.
     * 
     */
    private final String low;
    /**
     * @return The Medium database service provides a lower level of resources to each SQL statement potentially resulting a lower level of performance, but supports more concurrent SQL statements.
     * 
     */
    private final String medium;
    /**
     * @return A list of connection string profiles to allow clients to group, filter and select connection string values based on structured metadata.
     * 
     */
    private final List<GetAutonomousDatabasesClonesAutonomousDatabaseConnectionStringProfile> profiles;

    @CustomType.Constructor
    private GetAutonomousDatabasesClonesAutonomousDatabaseConnectionString(
        @CustomType.Parameter("allConnectionStrings") Map<String,Object> allConnectionStrings,
        @CustomType.Parameter("dedicated") String dedicated,
        @CustomType.Parameter("high") String high,
        @CustomType.Parameter("low") String low,
        @CustomType.Parameter("medium") String medium,
        @CustomType.Parameter("profiles") List<GetAutonomousDatabasesClonesAutonomousDatabaseConnectionStringProfile> profiles) {
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
        return this.allConnectionStrings;
    }
    /**
     * @return The database service provides the least level of resources to each SQL statement, but supports the most number of concurrent SQL statements.
     * 
     */
    public String dedicated() {
        return this.dedicated;
    }
    /**
     * @return The High database service provides the highest level of resources to each SQL statement resulting in the highest performance, but supports the fewest number of concurrent SQL statements.
     * 
     */
    public String high() {
        return this.high;
    }
    /**
     * @return The Low database service provides the least level of resources to each SQL statement, but supports the most number of concurrent SQL statements.
     * 
     */
    public String low() {
        return this.low;
    }
    /**
     * @return The Medium database service provides a lower level of resources to each SQL statement potentially resulting a lower level of performance, but supports more concurrent SQL statements.
     * 
     */
    public String medium() {
        return this.medium;
    }
    /**
     * @return A list of connection string profiles to allow clients to group, filter and select connection string values based on structured metadata.
     * 
     */
    public List<GetAutonomousDatabasesClonesAutonomousDatabaseConnectionStringProfile> profiles() {
        return this.profiles;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutonomousDatabasesClonesAutonomousDatabaseConnectionString defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private Map<String,Object> allConnectionStrings;
        private String dedicated;
        private String high;
        private String low;
        private String medium;
        private List<GetAutonomousDatabasesClonesAutonomousDatabaseConnectionStringProfile> profiles;

        public Builder() {
    	      // Empty
        }

        public Builder(GetAutonomousDatabasesClonesAutonomousDatabaseConnectionString defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.allConnectionStrings = defaults.allConnectionStrings;
    	      this.dedicated = defaults.dedicated;
    	      this.high = defaults.high;
    	      this.low = defaults.low;
    	      this.medium = defaults.medium;
    	      this.profiles = defaults.profiles;
        }

        public Builder allConnectionStrings(Map<String,Object> allConnectionStrings) {
            this.allConnectionStrings = Objects.requireNonNull(allConnectionStrings);
            return this;
        }
        public Builder dedicated(String dedicated) {
            this.dedicated = Objects.requireNonNull(dedicated);
            return this;
        }
        public Builder high(String high) {
            this.high = Objects.requireNonNull(high);
            return this;
        }
        public Builder low(String low) {
            this.low = Objects.requireNonNull(low);
            return this;
        }
        public Builder medium(String medium) {
            this.medium = Objects.requireNonNull(medium);
            return this;
        }
        public Builder profiles(List<GetAutonomousDatabasesClonesAutonomousDatabaseConnectionStringProfile> profiles) {
            this.profiles = Objects.requireNonNull(profiles);
            return this;
        }
        public Builder profiles(GetAutonomousDatabasesClonesAutonomousDatabaseConnectionStringProfile... profiles) {
            return profiles(List.of(profiles));
        }        public GetAutonomousDatabasesClonesAutonomousDatabaseConnectionString build() {
            return new GetAutonomousDatabasesClonesAutonomousDatabaseConnectionString(allConnectionStrings, dedicated, high, low, medium, profiles);
        }
    }
}
