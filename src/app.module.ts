import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { BookmarkModule } from './bookmark/bookmark.module';

@Module({
  imports: [AuthModule, BookmarkModule],
  controllers: [],
  providers: [],
})
export class AppModule {}
