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


public final class DbSystemDbHomeDatabaseConnectionStringArgs extends com.pulumi.resources.ResourceArgs {

    public static final DbSystemDbHomeDatabaseConnectionStringArgs Empty = new DbSystemDbHomeDatabaseConnectionStringArgs();

    @Import(name="allConnectionStrings")
    private @Nullable Output<Map<String,Object>> allConnectionStrings;

    public Optional<Output<Map<String,Object>>> allConnectionStrings() {
        return Optional.ofNullable(this.allConnectionStrings);
    }

    @Import(name="cdbDefault")
    private @Nullable Output<String> cdbDefault;

    public Optional<Output<String>> cdbDefault() {
        return Optional.ofNullable(this.cdbDefault);
    }

    @Import(name="cdbIpDefault")
    private @Nullable Output<String> cdbIpDefault;

    public Optional<Output<String>> cdbIpDefault() {
        return Optional.ofNullable(this.cdbIpDefault);
    }

    private DbSystemDbHomeDatabaseConnectionStringArgs() {}

    private DbSystemDbHomeDatabaseConnectionStringArgs(DbSystemDbHomeDatabaseConnectionStringArgs $) {
        this.allConnectionStrings = $.allConnectionStrings;
        this.cdbDefault = $.cdbDefault;
        this.cdbIpDefault = $.cdbIpDefault;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DbSystemDbHomeDatabaseConnectionStringArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DbSystemDbHomeDatabaseConnectionStringArgs $;

        public Builder() {
            $ = new DbSystemDbHomeDatabaseConnectionStringArgs();
        }

        public Builder(DbSystemDbHomeDatabaseConnectionStringArgs defaults) {
            $ = new DbSystemDbHomeDatabaseConnectionStringArgs(Objects.requireNonNull(defaults));
        }

        public Builder allConnectionStrings(@Nullable Output<Map<String,Object>> allConnectionStrings) {
            $.allConnectionStrings = allConnectionStrings;
            return this;
        }

        public Builder allConnectionStrings(Map<String,Object> allConnectionStrings) {
            return allConnectionStrings(Output.of(allConnectionStrings));
        }

        public Builder cdbDefault(@Nullable Output<String> cdbDefault) {
            $.cdbDefault = cdbDefault;
            return this;
        }

        public Builder cdbDefault(String cdbDefault) {
            return cdbDefault(Output.of(cdbDefault));
        }

        public Builder cdbIpDefault(@Nullable Output<String> cdbIpDefault) {
            $.cdbIpDefault = cdbIpDefault;
            return this;
        }

        public Builder cdbIpDefault(String cdbIpDefault) {
            return cdbIpDefault(Output.of(cdbIpDefault));
        }

        public DbSystemDbHomeDatabaseConnectionStringArgs build() {
            return $;
        }
    }

}