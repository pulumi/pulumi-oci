// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DbSystemDbSystemOptionsArgs extends com.pulumi.resources.ResourceArgs {

    public static final DbSystemDbSystemOptionsArgs Empty = new DbSystemDbSystemOptionsArgs();

    /**
     * The storage option used in DB system. ASM - Automatic storage management LVM - Logical Volume management
     * 
     */
    @Import(name="storageManagement")
    private @Nullable Output<String> storageManagement;

    /**
     * @return The storage option used in DB system. ASM - Automatic storage management LVM - Logical Volume management
     * 
     */
    public Optional<Output<String>> storageManagement() {
        return Optional.ofNullable(this.storageManagement);
    }

    private DbSystemDbSystemOptionsArgs() {}

    private DbSystemDbSystemOptionsArgs(DbSystemDbSystemOptionsArgs $) {
        this.storageManagement = $.storageManagement;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DbSystemDbSystemOptionsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DbSystemDbSystemOptionsArgs $;

        public Builder() {
            $ = new DbSystemDbSystemOptionsArgs();
        }

        public Builder(DbSystemDbSystemOptionsArgs defaults) {
            $ = new DbSystemDbSystemOptionsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param storageManagement The storage option used in DB system. ASM - Automatic storage management LVM - Logical Volume management
         * 
         * @return builder
         * 
         */
        public Builder storageManagement(@Nullable Output<String> storageManagement) {
            $.storageManagement = storageManagement;
            return this;
        }

        /**
         * @param storageManagement The storage option used in DB system. ASM - Automatic storage management LVM - Logical Volume management
         * 
         * @return builder
         * 
         */
        public Builder storageManagement(String storageManagement) {
            return storageManagement(Output.of(storageManagement));
        }

        public DbSystemDbSystemOptionsArgs build() {
            return $;
        }
    }

}
