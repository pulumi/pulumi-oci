// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DatabaseUpgradeConnectionStringArgs extends com.pulumi.resources.ResourceArgs {

    public static final DatabaseUpgradeConnectionStringArgs Empty = new DatabaseUpgradeConnectionStringArgs();

    /**
     * All connection strings to use to connect to the Database.
     * 
     */
    @Import(name="allConnectionStrings")
    private @Nullable Output<Map<String,Object>> allConnectionStrings;

    /**
     * @return All connection strings to use to connect to the Database.
     * 
     */
    public Optional<Output<Map<String,Object>>> allConnectionStrings() {
        return Optional.ofNullable(this.allConnectionStrings);
    }

    /**
     * Host name based CDB Connection String.
     * 
     */
    @Import(name="cdbDefault")
    private @Nullable Output<String> cdbDefault;

    /**
     * @return Host name based CDB Connection String.
     * 
     */
    public Optional<Output<String>> cdbDefault() {
        return Optional.ofNullable(this.cdbDefault);
    }

    /**
     * IP based CDB Connection String.
     * 
     */
    @Import(name="cdbIpDefault")
    private @Nullable Output<String> cdbIpDefault;

    /**
     * @return IP based CDB Connection String.
     * 
     */
    public Optional<Output<String>> cdbIpDefault() {
        return Optional.ofNullable(this.cdbIpDefault);
    }

    private DatabaseUpgradeConnectionStringArgs() {}

    private DatabaseUpgradeConnectionStringArgs(DatabaseUpgradeConnectionStringArgs $) {
        this.allConnectionStrings = $.allConnectionStrings;
        this.cdbDefault = $.cdbDefault;
        this.cdbIpDefault = $.cdbIpDefault;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DatabaseUpgradeConnectionStringArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DatabaseUpgradeConnectionStringArgs $;

        public Builder() {
            $ = new DatabaseUpgradeConnectionStringArgs();
        }

        public Builder(DatabaseUpgradeConnectionStringArgs defaults) {
            $ = new DatabaseUpgradeConnectionStringArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param allConnectionStrings All connection strings to use to connect to the Database.
         * 
         * @return builder
         * 
         */
        public Builder allConnectionStrings(@Nullable Output<Map<String,Object>> allConnectionStrings) {
            $.allConnectionStrings = allConnectionStrings;
            return this;
        }

        /**
         * @param allConnectionStrings All connection strings to use to connect to the Database.
         * 
         * @return builder
         * 
         */
        public Builder allConnectionStrings(Map<String,Object> allConnectionStrings) {
            return allConnectionStrings(Output.of(allConnectionStrings));
        }

        /**
         * @param cdbDefault Host name based CDB Connection String.
         * 
         * @return builder
         * 
         */
        public Builder cdbDefault(@Nullable Output<String> cdbDefault) {
            $.cdbDefault = cdbDefault;
            return this;
        }

        /**
         * @param cdbDefault Host name based CDB Connection String.
         * 
         * @return builder
         * 
         */
        public Builder cdbDefault(String cdbDefault) {
            return cdbDefault(Output.of(cdbDefault));
        }

        /**
         * @param cdbIpDefault IP based CDB Connection String.
         * 
         * @return builder
         * 
         */
        public Builder cdbIpDefault(@Nullable Output<String> cdbIpDefault) {
            $.cdbIpDefault = cdbIpDefault;
            return this;
        }

        /**
         * @param cdbIpDefault IP based CDB Connection String.
         * 
         * @return builder
         * 
         */
        public Builder cdbIpDefault(String cdbIpDefault) {
            return cdbIpDefault(Output.of(cdbIpDefault));
        }

        public DatabaseUpgradeConnectionStringArgs build() {
            return $;
        }
    }

}