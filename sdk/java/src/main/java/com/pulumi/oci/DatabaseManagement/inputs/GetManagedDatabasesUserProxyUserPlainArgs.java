// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetManagedDatabasesUserProxyUserPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetManagedDatabasesUserProxyUserPlainArgs Empty = new GetManagedDatabasesUserProxyUserPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     * 
     */
    @Import(name="managedDatabaseId", required=true)
    private String managedDatabaseId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     * 
     */
    public String managedDatabaseId() {
        return this.managedDatabaseId;
    }

    /**
     * A filter to return only resources that match the entire name.
     * 
     */
    @Import(name="name")
    private @Nullable String name;

    /**
     * @return A filter to return only resources that match the entire name.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * The name of the user whose details are to be viewed.
     * 
     */
    @Import(name="userName", required=true)
    private String userName;

    /**
     * @return The name of the user whose details are to be viewed.
     * 
     */
    public String userName() {
        return this.userName;
    }

    private GetManagedDatabasesUserProxyUserPlainArgs() {}

    private GetManagedDatabasesUserProxyUserPlainArgs(GetManagedDatabasesUserProxyUserPlainArgs $) {
        this.managedDatabaseId = $.managedDatabaseId;
        this.name = $.name;
        this.userName = $.userName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetManagedDatabasesUserProxyUserPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetManagedDatabasesUserProxyUserPlainArgs $;

        public Builder() {
            $ = new GetManagedDatabasesUserProxyUserPlainArgs();
        }

        public Builder(GetManagedDatabasesUserProxyUserPlainArgs defaults) {
            $ = new GetManagedDatabasesUserProxyUserPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param managedDatabaseId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
         * 
         * @return builder
         * 
         */
        public Builder managedDatabaseId(String managedDatabaseId) {
            $.managedDatabaseId = managedDatabaseId;
            return this;
        }

        /**
         * @param name A filter to return only resources that match the entire name.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable String name) {
            $.name = name;
            return this;
        }

        /**
         * @param userName The name of the user whose details are to be viewed.
         * 
         * @return builder
         * 
         */
        public Builder userName(String userName) {
            $.userName = userName;
            return this;
        }

        public GetManagedDatabasesUserProxyUserPlainArgs build() {
            if ($.managedDatabaseId == null) {
                throw new MissingRequiredPropertyException("GetManagedDatabasesUserProxyUserPlainArgs", "managedDatabaseId");
            }
            if ($.userName == null) {
                throw new MissingRequiredPropertyException("GetManagedDatabasesUserProxyUserPlainArgs", "userName");
            }
            return $;
        }
    }

}
