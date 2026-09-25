-- courses = 1 lets an account sort recipes into breakfast, lunch, dinner, dessert and snack, and plan the optional ones next to each dinner
ALTER TABLE accounts ADD COLUMN courses INTEGER NOT NULL DEFAULT 0;
